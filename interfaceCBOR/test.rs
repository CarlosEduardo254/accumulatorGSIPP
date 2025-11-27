use accumulator::{group::Rsa2048, Accumulator, MembershipProof};
use serde::Deserialize;

#[derive(Deserialize, serde::Serialize, Debug)]
struct Payload {
    #[serde(rename = "1")]
    id: String,
    #[serde(rename = "2")]
    timestamp: u64,
    #[serde(rename = "3")]
    reading: u64,
    #[serde(rename = "4", with = "serde_bytes")]
    membership_proof: Vec<u8>,
}

fn process_cbor(bytes: &[u8], acc: &Accumulator<Rsa2048, String>) -> anyhow::Result<()> {
    // 1. Deserialize CBOR to Payload struct
    let payload: Payload = serde_cbor::from_slice(bytes)?;
    println!("Recebido: {:?}", payload);

    // 2. Deserialize MembershipProof (witness + PoE) from bytes
    let proof: MembershipProof<Rsa2048, String> =
        serde_cbor::from_slice(&payload.membership_proof)?;

    // 3. Cryptographic verification using the accumulator's verify_membership method
    if acc.verify_membership(&payload.id, &proof) {
        println!("✓ PROVA CRIPTOGRÁFICA VÁLIDA!");
        println!("  Sensor ID: {}", payload.id);
        println!("  Timestamp: {}", payload.timestamp);
        println!("  Reading: {}", payload.reading);
        println!("  Verificação: witness^hash(id) == accumulator ✓");
    } else {
        println!("✗ PROVA INVÁLIDA!");
        println!(
            "  O sensor {} NÃO pertence ao acumulador ou a prova está corrompida",
            payload.id
        );
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    // Setup for demonstration
    let acc = Accumulator::<Rsa2048, String>::empty();
    let (acc, proof) = acc.add_with_proof(&["sensor-42".to_string()]);

    // Simulate CBOR creation (on the ESP side)
    // Now we serialize the COMPLETE MembershipProof (witness + PoE)
    let proof_bytes = serde_cbor::to_vec(&proof)?;

    let payload = Payload {
        id: "sensor-42".to_string(),
        timestamp: 1690000000,
        reading: 12,
        membership_proof: proof_bytes,
    };

    let raw_cbor = serde_cbor::to_vec(&payload)?;

    println!("═══════════════════════════════════════════════════");
    println!("CBOR payload created: {} bytes", raw_cbor.len());
    println!("  - Witness + PoE (prova criptográfica completa)");
    println!("═══════════════════════════════════════════════════\n");

    // Process the received CBOR
    process_cbor(&raw_cbor, &acc)?;

    Ok(())
}
