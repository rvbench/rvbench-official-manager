use clap::Parser;
#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: std::path::PathBuf,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config: rvbench_manager::Config = serde_json::from_slice(&std::fs::read(args.config)?)?;
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    let manager = rvbench_manager::Manager::open(config).await?;
    manager.start();
    axum::serve(listener, rvbench_manager::router(manager)).await?;
    Ok(())
}
