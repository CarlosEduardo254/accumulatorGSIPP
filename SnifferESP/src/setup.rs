use accumulator::{group::Rsa2048, Accumulator};
use std::collections::HashMap;
use std::fs;

fn main() -> anyhow::Result<()> {
    println!("═════════════════════════════════════════════════");
    println!("      Setup do Sistema de Sensores IoT");
    println!("═════════════════════════════════════════════════\n");

    // Lista de sensores autorizados
    let esp_ids = vec![
        "ESP-01".to_string(),
        "ESP-02".to_string(),
        "ESP-42".to_string(),
        // Adicione mais ESPs aqui conforme necessário
    ];

    println!("Gerando acumulador para {} sensores:", esp_ids.len());
    for id in &esp_ids {
        println!("  - {}", id);
    }
    println!();

    // 1. Criar acumulador vazio
    let mut acc = Accumulator::<Rsa2048, String>::empty();
    let mut all_proofs = HashMap::new();

    // 2. Adicionar cada ESP ao acumulador e gerar sua prova individual
    println!("Gerando provas de pertencimento...");
    for id in &esp_ids {
        let (new_acc, proof) = acc.add_with_proof(&[id.clone()]);
        all_proofs.insert(id.clone(), proof);
        acc = new_acc;
        println!("  ✓ Prova gerada para {}", id);
    }
    println!();

    // 3. Salvar acumulador serializado
    let acc_bytes = serde_cbor::to_vec(&acc)?;
    fs::write("accumulator.dat", &acc_bytes)?;
    println!(
        "✓ Acumulador salvo em 'accumulator.dat' ({} bytes)",
        acc_bytes.len()
    );

    // 4. Salvar provas individuais para cada ESP
    fs::create_dir_all("proofs")?;
    for (id, proof) in &all_proofs {
        let proof_bytes = serde_cbor::to_vec(proof)?;
        let filename = format!("proofs/{}.proof", id.replace("-", "_"));
        fs::write(&filename, &proof_bytes)?;
        println!(
            "✓ Prova salva em '{}' ({} bytes)",
            filename,
            proof_bytes.len()
        );
    }

    println!("\n═════════════════════════════════════════════════");
    println!("Setup completo!");
    println!("═════════════════════════════════════════════════");
    println!("\nPróximos passos:");
    println!("1. Copie o arquivo 'accumulator.dat' para onde vai rodar o controlador");
    println!("2. Para cada ESP, grave o arquivo '.proof' correspondente:");
    for id in &esp_ids {
        println!("   - {} → proofs/{}.proof", id, id.replace("-", "_"));
    }
    println!("\n3. No ESP, carregue a prova e envie junto com os dados via CBOR");
    println!("4. Execute o controlador: cd SnifferESP && cargo run --release\n");

    Ok(())
}
