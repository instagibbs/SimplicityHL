use std::collections::HashMap;
use std::str::FromStr;

use elements::hashes::Hash;
use elements::pset::PartiallySignedTransaction as Psbt;
use elements::secp256k1_zkp as secp256k1;
use elements::confidential;
use elementsd::bitcoincore_rpc::jsonrpc::serde_json::json;
use elementsd::ElementsD;
use secp256k1::hashes::{sha256, HashEngine};
use secp256k1::XOnlyPublicKey;
use simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::str::WitnessName;
use simplicityhl::value::ValueConstructible;
use simplicityhl::{elements, simplicity, Value};

mod common;
use common::daemon::Call;
use common::util;

const SPEND_DELAY: u16 = 10;

fn setup() -> (ElementsD, elements::BlockHash) {
    let mut conf = elementsd::Conf::new(None);
    let arg_pos = conf
        .0
        .args
        .iter()
        .position(|x| x.starts_with("-initialfreecoins="));
    match arg_pos {
        Some(i) => conf.0.args[i] = "-initialfreecoins=210000000000",
        None => conf.0.args.push("-initialfreecoins=210000000000"),
    };
    conf.0.args.push("-evbparams=simplicity:-1:::");
    conf.0.args.push("-txindex=1");

    let elementsd = ElementsD::with_conf(elementsd::exe_path().unwrap(), &conf).unwrap();
    let create = elementsd.call("createwallet", &["wallet".into()]);
    assert_eq!(create.get("name").unwrap(), "wallet");
    let rescan = elementsd.call("rescanblockchain", &[]);
    assert_eq!(rescan.get("stop_height").unwrap().as_u64().unwrap(), 0);

    let genesis_str = elementsd.call("getblockhash", &[0u32.into()]);
    let genesis_str = genesis_str.as_str().unwrap();
    let genesis_hash = elements::BlockHash::from_str(genesis_str).unwrap();
    (elementsd, genesis_hash)
}

fn internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .expect("NUMS point should be valid")
}

// Compute build_tapleaf_simplicity(cmr) in Rust.
// SHA256(SHA256("TapLeaf/elements") || SHA256("TapLeaf/elements")
//        || 0xbe || 0x20 || cmr)
fn tapleaf_simplicity_hash(cmr: &[u8; 32]) -> [u8; 32] {
    let tag = sha256::Hash::hash(b"TapLeaf/elements");
    let mut eng = sha256::HashEngine::default();
    eng.input(tag.as_byte_array());
    eng.input(tag.as_byte_array());
    eng.input(&[0xbe]); // Simplicity leaf version
    eng.input(&[0x20]); // 32 bytes length
    eng.input(cmr);
    sha256::Hash::from_engine(eng).to_byte_array()
}

// Compute build_tapbranch(a, b) in Rust.
// Sorts inputs lexicographically before hashing.
#[allow(dead_code)]
fn tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let tag = sha256::Hash::hash(b"TapBranch/elements");
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    let mut eng = sha256::HashEngine::default();
    eng.input(tag.as_byte_array());
    eng.input(tag.as_byte_array());
    eng.input(left);
    eng.input(right);
    sha256::Hash::from_engine(eng).to_byte_array()
}

struct VaultScripts {
    trigger: simplicityhl::CompiledProgram,
    complete: simplicityhl::CompiledProgram,
    recover: simplicityhl::CompiledProgram,
}

fn compile_vault_scripts(recovery_spk_hash: [u8; 32]) -> VaultScripts {
    let recover_text =
        std::fs::read_to_string("../examples/vault_recover.simf").expect("read recover");
    let complete_text =
        std::fs::read_to_string("../examples/vault_complete.simf").expect("read complete");
    let trigger_text =
        std::fs::read_to_string("../examples/vault_trigger.simf").expect("read trigger");

    let recover_args = simplicityhl::Arguments::from(HashMap::from([(
        WitnessName::from_str_unchecked("RECOVERY_SPK_HASH"),
        Value::u256(simplicityhl::num::U256::from_byte_array(recovery_spk_hash)),
    )]));
    let recover = simplicityhl::CompiledProgram::new(recover_text.as_str(), recover_args, false)
        .expect("recover should compile");

    let complete_args = simplicityhl::Arguments::from(HashMap::from([(
        WitnessName::from_str_unchecked("SPEND_DELAY"),
        Value::u16(SPEND_DELAY),
    )]));
    let complete = simplicityhl::CompiledProgram::new(complete_text.as_str(), complete_args, false)
        .expect("complete should compile");

    let complete_cmr = complete.commit().cmr();
    let trigger_args = simplicityhl::Arguments::from(HashMap::from([
        (
            WitnessName::from_str_unchecked("TRIGGER_PUBKEY"),
            Value::u256(util::xonly_public_key(1)),
        ),
        (
            WitnessName::from_str_unchecked("COMPLETE_CMR"),
            Value::u256(simplicityhl::num::U256::from_byte_array(
                complete_cmr.to_byte_array(),
            )),
        ),
    ]));
    let trigger = simplicityhl::CompiledProgram::new(trigger_text.as_str(), trigger_args, false)
        .expect("trigger should compile");

    VaultScripts {
        trigger,
        complete,
        recover,
    }
}

fn script_ver(
    compiled: &simplicityhl::CompiledProgram,
) -> (elements::Script, elements::taproot::LeafVersion) {
    let script = elements::Script::from(compiled.commit().cmr().as_ref().to_vec());
    (script, simplicity::leaf_version())
}

fn build_vault_taptree(
    scripts: &VaultScripts,
) -> elements::taproot::TaprootSpendInfo {
    let (trigger_script, trigger_ver) = script_ver(&scripts.trigger);
    let (recover_script, recover_ver) = script_ver(&scripts.recover);
    elements::taproot::TaprootBuilder::new()
        .add_leaf_with_ver(1, trigger_script, trigger_ver)
        .expect("valid leaf")
        .add_leaf_with_ver(1, recover_script, recover_ver)
        .expect("valid leaf")
        .finalize(secp256k1::SECP256K1, internal_key())
        .expect("valid taptree")
}

fn build_triggered_taptree(
    scripts: &VaultScripts,
    target_hash: &[u8; 32],
) -> elements::taproot::TaprootSpendInfo {
    let (complete_script, complete_ver) = script_ver(&scripts.complete);
    let (recover_script, recover_ver) = script_ver(&scripts.recover);
    let state_leaf = tapleaf_simplicity_hash(target_hash);
    let state_leaf_sha = sha256::Hash::from_byte_array(state_leaf);
    elements::taproot::TaprootBuilder::new()
        .add_leaf_with_ver(2, complete_script, complete_ver)
        .expect("valid leaf")
        .add_hidden(2, state_leaf_sha)
        .expect("valid hidden node")
        .add_leaf_with_ver(1, recover_script, recover_ver)
        .expect("valid leaf")
        .finalize(secp256k1::SECP256K1, internal_key())
        .expect("valid taptree")
}

fn spk_hash(spk: &elements::Script) -> [u8; 32] {
    sha256::Hash::hash(spk.as_bytes()).to_byte_array()
}

// Compute the CTV hash matching ctv.simf's field order.
// This replicates the Simplicity C library's hash construction.
fn compute_ctv_hash(tx: &elements::Transaction, input_index: u32) -> [u8; 32] {
    let input_script_sigs_hash = {
        let mut eng = sha256::HashEngine::default();
        for input in &tx.input {
            let h = sha256::Hash::hash(input.script_sig.as_bytes());
            eng.input(h.as_byte_array());
        }
        sha256::Hash::from_engine(eng)
    };

    let input_sequences_hash = {
        let mut eng = sha256::HashEngine::default();
        for input in &tx.input {
            eng.input(&input.sequence.to_consensus_u32().to_be_bytes());
        }
        sha256::Hash::from_engine(eng)
    };

    let outputs_hash = compute_outputs_hash(tx);

    let mut eng = sha256::HashEngine::default();
    eng.input(&(tx.version as u32).to_be_bytes());
    eng.input(&tx.lock_time.to_consensus_u32().to_be_bytes());
    eng.input(input_script_sigs_hash.as_byte_array());
    eng.input(&(tx.input.len() as u32).to_be_bytes());
    eng.input(input_sequences_hash.as_byte_array());
    eng.input(&(tx.output.len() as u32).to_be_bytes());
    eng.input(outputs_hash.as_byte_array());
    eng.input(&input_index.to_be_bytes());
    sha256::Hash::from_engine(eng).to_byte_array()
}

fn compute_outputs_hash(tx: &elements::Transaction) -> sha256::Hash {
    let mut eng_asset_amounts = sha256::HashEngine::default();
    let mut eng_nonces = sha256::HashEngine::default();
    let mut eng_scripts = sha256::HashEngine::default();
    let mut eng_range_proofs = sha256::HashEngine::default();

    for output in &tx.output {
        // Asset + Amount (into the same context)
        hash_conf_asset(&mut eng_asset_amounts, &output.asset);
        hash_conf_amount(&mut eng_asset_amounts, &output.value);

        // Nonce
        match &output.nonce {
            confidential::Nonce::Null => eng_nonces.input(&[0x00]),
            confidential::Nonce::Explicit(n) => {
                eng_nonces.input(&[0x01]);
                eng_nonces.input(n);
            }
            _ => panic!("confidential nonces not supported"),
        }

        // Script hash
        let script_hash = sha256::Hash::hash(output.script_pubkey.as_bytes());
        eng_scripts.input(script_hash.as_byte_array());

        // Range proof hash
        let rp_vec;
        let proof_bytes: &[u8] = match &output.witness.rangeproof {
            Some(p) => {
                rp_vec = p.serialize();
                &rp_vec
            }
            None => &[],
        };
        let proof_hash = sha256::Hash::hash(proof_bytes);
        eng_range_proofs.input(proof_hash.as_byte_array());
    }

    let asset_amounts_hash = sha256::Hash::from_engine(eng_asset_amounts);
    let nonces_hash = sha256::Hash::from_engine(eng_nonces);
    let scripts_hash = sha256::Hash::from_engine(eng_scripts);
    let range_proofs_hash = sha256::Hash::from_engine(eng_range_proofs);

    let mut eng = sha256::HashEngine::default();
    eng.input(asset_amounts_hash.as_byte_array());
    eng.input(nonces_hash.as_byte_array());
    eng.input(scripts_hash.as_byte_array());
    eng.input(range_proofs_hash.as_byte_array());
    sha256::Hash::from_engine(eng)
}

fn hash_conf_asset(eng: &mut sha256::HashEngine, asset: &confidential::Asset) {
    match asset {
        confidential::Asset::Explicit(id) => {
            eng.input(&[0x01]);
            eng.input(&asset_id_bytes(id));
        }
        confidential::Asset::Null => eng.input(&[0x00]),
        _ => panic!("confidential assets not supported"),
    }
}

fn hash_conf_amount(eng: &mut sha256::HashEngine, value: &confidential::Value) {
    match value {
        confidential::Value::Explicit(amt) => {
            eng.input(&[0x01]);
            eng.input(&amt.to_be_bytes());
        }
        confidential::Value::Null => eng.input(&[0x00]),
        _ => panic!("confidential values not supported"),
    }
}

fn asset_id_bytes(id: &elements::AssetId) -> [u8; 32] {
    id.into_inner().to_byte_array()
}

fn prioritise_and_send(daemon: &ElementsD, tx: &elements::Transaction) -> elements::Txid {
    let txid = tx.txid();
    daemon.call(
        "prioritisetransaction",
        &[json!(txid.to_string()), json!(0), json!(100_000_000i64)],
    );
    daemon.send_raw_transaction(tx)
}

fn get_raw_transaction(daemon: &ElementsD, txid: &elements::Txid) -> elements::Transaction {
    let hex = daemon
        .call("getrawtransaction", &[json!(txid.to_string())])
        .as_str()
        .expect("hex string")
        .to_string();
    let bytes: Vec<u8> = elements::hex::FromHex::from_hex(&hex).expect("valid hex");
    elements::encode::deserialize(&bytes).expect("valid tx")
}

fn build_simplicity_spend(
    compiled: &simplicityhl::CompiledProgram,
    witness_values: simplicityhl::WitnessValues,
    spend_info: &elements::taproot::TaprootSpendInfo,
    tx: &elements::Transaction,
    utxos: Vec<ElementsUtxo>,
    input_index: u32,
    genesis_hash: elements::BlockHash,
) -> Vec<Vec<u8>> {
    use std::sync::Arc;

    let (script, version) = script_ver(compiled);
    let script_ver = (script, version);
    let control_block = spend_info
        .control_block(&script_ver)
        .expect("control block should exist");
    let tx_arc = Arc::new(tx.clone());
    let env = ElementsEnv::new(
        tx_arc,
        utxos,
        input_index,
        compiled.commit().cmr(),
        control_block.clone(),
        None,
        genesis_hash,
    );
    let satisfied = compiled
        .satisfy_with_env(witness_values, Some(&env))
        .expect("program should be satisfiable");
    let (program_bytes, witness_bytes) = satisfied.redeem().to_vec_with_witness();
    vec![
        witness_bytes,
        program_bytes,
        script_ver.0.into_bytes(),
        control_block.serialize(),
    ]
}

fn fund_address(
    daemon: &ElementsD,
    address: &elements::Address,
) -> (elements::Txid, u32, elements::TxOut) {
    let txid = daemon.send_to_address(address, "1");
    daemon.generate(1);
    let tx = daemon.get_transaction(&txid);
    let target_spk = address.script_pubkey();
    for (vout, txout) in tx.output.iter().enumerate() {
        if txout.script_pubkey == target_spk
            && txout.value == confidential::Value::Explicit(100_000_000)
        {
            return (txid, vout as u32, txout.clone());
        }
    }
    panic!("funded output not found")
}

fn vault_address(
    spend_info: &elements::taproot::TaprootSpendInfo,
) -> elements::Address {
    elements::Address::p2tr(
        secp256k1::SECP256K1,
        spend_info.internal_key(),
        spend_info.merkle_root(),
        None,
        &elements::AddressParams::ELEMENTS,
    )
}

#[test]
fn vault_trigger_and_complete() {
    let (daemon, genesis_hash) = setup();
    let recovery_addr = daemon.get_new_address();
    let destination_addr = daemon.get_new_address();

    let scripts = compile_vault_scripts(spk_hash(&recovery_addr.script_pubkey()));
    let vault_info = build_vault_taptree(&scripts);
    let vault_addr = vault_address(&vault_info);

    // Fund the vault
    let (fund_txid, fund_vout, fund_utxo) = fund_address(&daemon, &vault_addr);
    let asset = fund_utxo.asset;
    let _explicit_asset = asset.explicit().expect("explicit asset");

    // Build the complete transaction template to compute CTV hash.
    // The CTV hash does NOT include input outpoints, so we can compute
    // it before knowing the triggered UTXO's outpoint.
    let complete_tx_template = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            // Outpoint is irrelevant for CTV hash
            previous_output: elements::OutPoint::default(),
            is_pegin: false,
            script_sig: elements::Script::new(),
            sequence: elements::Sequence::from_consensus(SPEND_DELAY as u32),
            asset_issuance: elements::AssetIssuance::null(),
            witness: elements::TxInWitness::empty(),
        }],
        output: vec![elements::TxOut {
            value: confidential::Value::Explicit(100_000_000),
            script_pubkey: destination_addr.script_pubkey(),
            asset,
            nonce: confidential::Nonce::Null,
            witness: elements::TxOutWitness::empty(),
        }],
    };
    let target_hash = compute_ctv_hash(&complete_tx_template, 0);

    // Build the triggered taptree
    let triggered_info = build_triggered_taptree(&scripts, &target_hash);
    let triggered_addr = vault_address(&triggered_info);

    // Build trigger transaction (zero fee)
    let trigger_tx = {
        let mut psbt = Psbt::from_tx(elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint::new(fund_txid, fund_vout),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence: elements::Sequence::ZERO,
                asset_issuance: elements::AssetIssuance::null(),
                witness: elements::TxInWitness::empty(),
            }],
            output: vec![elements::TxOut {
                value: confidential::Value::Explicit(100_000_000),
                script_pubkey: triggered_addr.script_pubkey(),
                asset,
                nonce: confidential::Nonce::Null,
                witness: elements::TxOutWitness::empty(),
            }],
        });

        let tx = psbt
            .extract_tx()
            .expect("extractable");
        let sighash_all = {
            let utxos = vec![ElementsUtxo::from(fund_utxo.clone())];
            let (script, version) = script_ver(&scripts.trigger);
            let control_block = vault_info
                .control_block(&(script, version))
                .expect("control block");
            let env = ElementsEnv::new(
                std::sync::Arc::new(tx.clone()),
                utxos.clone(),
                0,
                scripts.trigger.commit().cmr(),
                control_block,
                None,
                genesis_hash,
            );
            env.c_tx_env().sighash_all()
        };

        let mut witness_values = HashMap::new();
        witness_values.insert(
            WitnessName::from_str_unchecked("TRIGGER_SIG"),
            Value::byte_array(util::sign_schnorr(1, sighash_all.to_byte_array())),
        );
        witness_values.insert(
            WitnessName::from_str_unchecked("TARGET_HASH"),
            Value::u256(simplicityhl::num::U256::from_byte_array(target_hash)),
        );
        witness_values.insert(
            WitnessName::from_str_unchecked("TRIGGER_VOUT_IDX"),
            Value::u32(0),
        );
        let witness = simplicityhl::WitnessValues::from(witness_values);

        let utxos = vec![ElementsUtxo::from(fund_utxo)];
        let wit = build_simplicity_spend(
            &scripts.trigger,
            witness,
            &vault_info,
            &tx,
            utxos,
            0,
            genesis_hash,
        );
        psbt.inputs_mut()[0].final_script_witness = Some(wit);
        psbt.extract_tx().expect("extractable")
    };

    println!("Submitting trigger tx...");
    let trigger_txid = prioritise_and_send(&daemon, &trigger_tx);
    daemon.generate(1);

    // Find the triggered UTXO
    let trigger_out_tx = get_raw_transaction(&daemon, &trigger_txid);
    let mut triggered_vout = 0u32;
    let mut triggered_utxo = None;
    for (vout, txout) in trigger_out_tx.output.iter().enumerate() {
        if txout.script_pubkey == triggered_addr.script_pubkey() {
            triggered_vout = vout as u32;
            triggered_utxo = Some(txout.clone());
            break;
        }
    }
    let triggered_utxo = triggered_utxo.expect("triggered output should exist");

    // Mine SPEND_DELAY blocks for CSV
    daemon.generate(SPEND_DELAY as u32);

    // Build the actual complete transaction (with correct outpoint)
    let complete_tx = {
        let mut psbt = Psbt::from_tx(elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint::new(trigger_txid, triggered_vout),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence: elements::Sequence::from_consensus(SPEND_DELAY as u32),
                asset_issuance: elements::AssetIssuance::null(),
                witness: elements::TxInWitness::empty(),
            }],
            output: vec![elements::TxOut {
                value: confidential::Value::Explicit(100_000_000),
                script_pubkey: destination_addr.script_pubkey(),
                asset,
                nonce: confidential::Nonce::Null,
                witness: elements::TxOutWitness::empty(),
            }],
        });

        let tx = psbt
            .extract_tx()
            .expect("extractable");

        let mut witness_values = HashMap::new();
        witness_values.insert(
            WitnessName::from_str_unchecked("TARGET_HASH"),
            Value::u256(simplicityhl::num::U256::from_byte_array(target_hash)),
        );
        let witness = simplicityhl::WitnessValues::from(witness_values);

        let utxos = vec![ElementsUtxo::from(triggered_utxo)];
        let wit = build_simplicity_spend(
            &scripts.complete,
            witness,
            &triggered_info,
            &tx,
            utxos,
            0,
            genesis_hash,
        );
        psbt.inputs_mut()[0].final_script_witness = Some(wit);
        psbt.extract_tx().expect("extractable")
    };

    println!("Submitting complete tx...");
    let _complete_txid = prioritise_and_send(&daemon, &complete_tx);
    daemon.generate(1);
    println!("vault_trigger_and_complete: PASSED");
}

#[test]
fn vault_recovery() {
    let (daemon, genesis_hash) = setup();
    let recovery_addr = daemon.get_new_address();

    let scripts = compile_vault_scripts(spk_hash(&recovery_addr.script_pubkey()));
    let vault_info = build_vault_taptree(&scripts);
    let vault_addr = vault_address(&vault_info);

    // Fund the vault
    let (fund_txid, fund_vout, fund_utxo) = fund_address(&daemon, &vault_addr);
    let asset = fund_utxo.asset;

    // Build recovery transaction (zero fee, 1 output)
    let recover_tx = {
        let mut psbt = Psbt::from_tx(elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint::new(fund_txid, fund_vout),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence: elements::Sequence::ZERO,
                asset_issuance: elements::AssetIssuance::null(),
                witness: elements::TxInWitness::empty(),
            }],
            output: vec![elements::TxOut {
                value: confidential::Value::Explicit(100_000_000),
                script_pubkey: recovery_addr.script_pubkey(),
                asset,
                nonce: confidential::Nonce::Null,
                witness: elements::TxOutWitness::empty(),
            }],
        });

        let tx = psbt
            .extract_tx()
            .expect("extractable");
        let witness = simplicityhl::WitnessValues::default();
        let utxos = vec![ElementsUtxo::from(fund_utxo)];
        let wit = build_simplicity_spend(
            &scripts.recover,
            witness,
            &vault_info,
            &tx,
            utxos,
            0,
            genesis_hash,
        );
        psbt.inputs_mut()[0].final_script_witness = Some(wit);
        psbt.extract_tx().expect("extractable")
    };

    println!("Submitting recovery tx...");
    let _recovery_txid = prioritise_and_send(&daemon, &recover_tx);
    daemon.generate(1);
    println!("vault_recovery: PASSED");
}

#[test]
fn vault_recovery_after_trigger() {
    let (daemon, genesis_hash) = setup();
    let recovery_addr = daemon.get_new_address();
    let destination_addr = daemon.get_new_address();

    let scripts = compile_vault_scripts(spk_hash(&recovery_addr.script_pubkey()));
    let vault_info = build_vault_taptree(&scripts);
    let vault_addr = vault_address(&vault_info);

    // Fund and trigger (same as happy path)
    let (fund_txid, fund_vout, fund_utxo) = fund_address(&daemon, &vault_addr);
    let asset = fund_utxo.asset;

    let complete_tx_template = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            previous_output: elements::OutPoint::default(),
            is_pegin: false,
            script_sig: elements::Script::new(),
            sequence: elements::Sequence::from_consensus(SPEND_DELAY as u32),
            asset_issuance: elements::AssetIssuance::null(),
            witness: elements::TxInWitness::empty(),
        }],
        output: vec![elements::TxOut {
            value: confidential::Value::Explicit(100_000_000),
            script_pubkey: destination_addr.script_pubkey(),
            asset,
            nonce: confidential::Nonce::Null,
            witness: elements::TxOutWitness::empty(),
        }],
    };
    let target_hash = compute_ctv_hash(&complete_tx_template, 0);
    let triggered_info = build_triggered_taptree(&scripts, &target_hash);
    let triggered_addr = vault_address(&triggered_info);

    // Trigger
    let trigger_tx = {
        let mut psbt = Psbt::from_tx(elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint::new(fund_txid, fund_vout),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence: elements::Sequence::ZERO,
                asset_issuance: elements::AssetIssuance::null(),
                witness: elements::TxInWitness::empty(),
            }],
            output: vec![elements::TxOut {
                value: confidential::Value::Explicit(100_000_000),
                script_pubkey: triggered_addr.script_pubkey(),
                asset,
                nonce: confidential::Nonce::Null,
                witness: elements::TxOutWitness::empty(),
            }],
        });

        let tx = psbt
            .extract_tx()
            .expect("extractable");
        let sighash_all = {
            let utxos = vec![ElementsUtxo::from(fund_utxo.clone())];
            let (script, version) = script_ver(&scripts.trigger);
            let control_block = vault_info
                .control_block(&(script, version))
                .expect("control block");
            let env = ElementsEnv::new(
                std::sync::Arc::new(tx.clone()),
                utxos,
                0,
                scripts.trigger.commit().cmr(),
                control_block,
                None,
                genesis_hash,
            );
            env.c_tx_env().sighash_all()
        };

        let mut witness_values = HashMap::new();
        witness_values.insert(
            WitnessName::from_str_unchecked("TRIGGER_SIG"),
            Value::byte_array(util::sign_schnorr(1, sighash_all.to_byte_array())),
        );
        witness_values.insert(
            WitnessName::from_str_unchecked("TARGET_HASH"),
            Value::u256(simplicityhl::num::U256::from_byte_array(target_hash)),
        );
        witness_values.insert(
            WitnessName::from_str_unchecked("TRIGGER_VOUT_IDX"),
            Value::u32(0),
        );
        let witness = simplicityhl::WitnessValues::from(witness_values);
        let utxos = vec![ElementsUtxo::from(fund_utxo)];
        let wit = build_simplicity_spend(
            &scripts.trigger,
            witness,
            &vault_info,
            &tx,
            utxos,
            0,
            genesis_hash,
        );
        psbt.inputs_mut()[0].final_script_witness = Some(wit);
        psbt.extract_tx().expect("extractable")
    };

    let trigger_txid = prioritise_and_send(&daemon, &trigger_tx);
    daemon.generate(1);

    // Find the triggered UTXO
    let trigger_out_tx = get_raw_transaction(&daemon, &trigger_txid);
    let mut triggered_vout = 0u32;
    let mut triggered_utxo = None;
    for (vout, txout) in trigger_out_tx.output.iter().enumerate() {
        if txout.script_pubkey == triggered_addr.script_pubkey() {
            triggered_vout = vout as u32;
            triggered_utxo = Some(txout.clone());
            break;
        }
    }
    let triggered_utxo = triggered_utxo.expect("triggered output should exist");

    // Recover from the TRIGGERED state (not the vault state)
    let recover_tx = {
        let mut psbt = Psbt::from_tx(elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint::new(trigger_txid, triggered_vout),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence: elements::Sequence::ZERO,
                asset_issuance: elements::AssetIssuance::null(),
                witness: elements::TxInWitness::empty(),
            }],
            output: vec![elements::TxOut {
                value: confidential::Value::Explicit(100_000_000),
                script_pubkey: recovery_addr.script_pubkey(),
                asset,
                nonce: confidential::Nonce::Null,
                witness: elements::TxOutWitness::empty(),
            }],
        });

        let tx = psbt
            .extract_tx()
            .expect("extractable");
        let witness = simplicityhl::WitnessValues::default();
        let utxos = vec![ElementsUtxo::from(triggered_utxo)];
        let wit = build_simplicity_spend(
            &scripts.recover,
            witness,
            &triggered_info,
            &tx,
            utxos,
            0,
            genesis_hash,
        );
        psbt.inputs_mut()[0].final_script_witness = Some(wit);
        psbt.extract_tx().expect("extractable")
    };

    println!("Submitting recovery tx from triggered state...");
    let _recovery_txid = prioritise_and_send(&daemon, &recover_tx);
    daemon.generate(1);
    println!("vault_recovery_after_trigger: PASSED");
}

#[test]
fn vault_batch_trigger() {
    let (daemon, genesis_hash) = setup();
    let recovery_addr = daemon.get_new_address();
    let destinations: Vec<_> = (0..3).map(|_| daemon.get_new_address()).collect();

    let scripts = compile_vault_scripts(spk_hash(&recovery_addr.script_pubkey()));
    let vault_info = build_vault_taptree(&scripts);
    let vault_addr = vault_address(&vault_info);

    // Fund 3 separate vault UTXOs
    let funds: Vec<_> = (0..3)
        .map(|_| fund_address(&daemon, &vault_addr))
        .collect();
    let asset = funds[0].2.asset;

    // Build per-vault complete tx templates and compute CTV hashes
    let target_hashes: Vec<[u8; 32]> = destinations
        .iter()
        .map(|dest| {
            let template = elements::Transaction {
                version: 2,
                lock_time: elements::LockTime::ZERO,
                input: vec![elements::TxIn {
                    previous_output: elements::OutPoint::default(),
                    is_pegin: false,
                    script_sig: elements::Script::new(),
                    sequence: elements::Sequence::from_consensus(SPEND_DELAY as u32),
                    asset_issuance: elements::AssetIssuance::null(),
                    witness: elements::TxInWitness::empty(),
                }],
                output: vec![elements::TxOut {
                    value: confidential::Value::Explicit(100_000_000),
                    script_pubkey: dest.script_pubkey(),
                    asset,
                    nonce: confidential::Nonce::Null,
                    witness: elements::TxOutWitness::empty(),
                }],
            };
            compute_ctv_hash(&template, 0)
        })
        .collect();

    // Build triggered taptrees (one per vault, each with its own target hash)
    let triggered_infos: Vec<_> = target_hashes
        .iter()
        .map(|th| build_triggered_taptree(&scripts, th))
        .collect();
    let triggered_addrs: Vec<_> = triggered_infos.iter().map(|i| vault_address(i)).collect();

    // Build single trigger tx with 3 inputs and 3 outputs (zero fee)
    let trigger_tx = {
        let inputs: Vec<_> = funds
            .iter()
            .map(|(txid, vout, _)| elements::TxIn {
                previous_output: elements::OutPoint::new(*txid, *vout),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence: elements::Sequence::ZERO,
                asset_issuance: elements::AssetIssuance::null(),
                witness: elements::TxInWitness::empty(),
            })
            .collect();
        let outputs: Vec<_> = triggered_addrs
            .iter()
            .map(|addr| elements::TxOut {
                value: confidential::Value::Explicit(100_000_000),
                script_pubkey: addr.script_pubkey(),
                asset,
                nonce: confidential::Nonce::Null,
                witness: elements::TxOutWitness::empty(),
            })
            .collect();

        let mut psbt = Psbt::from_tx(elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: inputs,
            output: outputs,
        });

        let tx = psbt.extract_tx().expect("extractable");

        // Compute sighash_all and build witness for each input
        for i in 0..3u32 {
            let _fund_utxo = &funds[i as usize].2;
            let sighash_all = {
                let utxos: Vec<_> = funds
                    .iter()
                    .map(|(_, _, utxo)| ElementsUtxo::from(utxo.clone()))
                    .collect();
                let (script, version) = script_ver(&scripts.trigger);
                let control_block = vault_info
                    .control_block(&(script, version))
                    .expect("control block");
                let env = ElementsEnv::new(
                    std::sync::Arc::new(tx.clone()),
                    utxos,
                    i,
                    scripts.trigger.commit().cmr(),
                    control_block,
                    None,
                    genesis_hash,
                );
                env.c_tx_env().sighash_all()
            };

            let mut witness_values = HashMap::new();
            witness_values.insert(
                WitnessName::from_str_unchecked("TRIGGER_SIG"),
                Value::byte_array(util::sign_schnorr(
                    1,
                    sighash_all.to_byte_array(),
                )),
            );
            witness_values.insert(
                WitnessName::from_str_unchecked("TARGET_HASH"),
                Value::u256(simplicityhl::num::U256::from_byte_array(
                    target_hashes[i as usize],
                )),
            );
            witness_values.insert(
                WitnessName::from_str_unchecked("TRIGGER_VOUT_IDX"),
                Value::u32(i),
            );
            let witness = simplicityhl::WitnessValues::from(witness_values);

            let utxos: Vec<_> = funds
                .iter()
                .map(|(_, _, utxo)| ElementsUtxo::from(utxo.clone()))
                .collect();
            let wit = build_simplicity_spend(
                &scripts.trigger,
                witness,
                &vault_info,
                &tx,
                utxos,
                i,
                genesis_hash,
            );
            psbt.inputs_mut()[i as usize].final_script_witness = Some(wit);
        }
        psbt.extract_tx().expect("extractable")
    };

    println!("Submitting batch trigger tx (3 inputs)...");
    let trigger_txid = prioritise_and_send(&daemon, &trigger_tx);
    daemon.generate(1);

    // Mine SPEND_DELAY blocks for CSV
    daemon.generate(SPEND_DELAY as u32);

    // Complete all 3 in individual transactions
    let trigger_out_tx = get_raw_transaction(&daemon, &trigger_txid);
    for i in 0..3u32 {
        let triggered_spk = triggered_addrs[i as usize].script_pubkey();
        let mut triggered_vout = 0u32;
        let mut triggered_utxo = None;
        for (vout, txout) in trigger_out_tx.output.iter().enumerate() {
            if txout.script_pubkey == triggered_spk {
                triggered_vout = vout as u32;
                triggered_utxo = Some(txout.clone());
                break;
            }
        }
        let triggered_utxo = triggered_utxo.expect("triggered output");

        let complete_tx = {
            let mut psbt = Psbt::from_tx(elements::Transaction {
                version: 2,
                lock_time: elements::LockTime::ZERO,
                input: vec![elements::TxIn {
                    previous_output: elements::OutPoint::new(
                        trigger_txid,
                        triggered_vout,
                    ),
                    is_pegin: false,
                    script_sig: elements::Script::new(),
                    sequence: elements::Sequence::from_consensus(SPEND_DELAY as u32),
                    asset_issuance: elements::AssetIssuance::null(),
                    witness: elements::TxInWitness::empty(),
                }],
                output: vec![elements::TxOut {
                    value: confidential::Value::Explicit(100_000_000),
                    script_pubkey: destinations[i as usize].script_pubkey(),
                    asset,
                    nonce: confidential::Nonce::Null,
                    witness: elements::TxOutWitness::empty(),
                }],
            });

            let tx = psbt.extract_tx().expect("extractable");
            let mut witness_values = HashMap::new();
            witness_values.insert(
                WitnessName::from_str_unchecked("TARGET_HASH"),
                Value::u256(simplicityhl::num::U256::from_byte_array(
                    target_hashes[i as usize],
                )),
            );
            let witness = simplicityhl::WitnessValues::from(witness_values);
            let utxos = vec![ElementsUtxo::from(triggered_utxo)];
            let wit = build_simplicity_spend(
                &scripts.complete,
                witness,
                &triggered_infos[i as usize],
                &tx,
                utxos,
                0,
                genesis_hash,
            );
            psbt.inputs_mut()[0].final_script_witness = Some(wit);
            psbt.extract_tx().expect("extractable")
        };

        println!("Completing vault {i}...");
        let _txid = prioritise_and_send(&daemon, &complete_tx);
        daemon.generate(1);
    }
    println!("vault_batch_trigger: PASSED");
}
