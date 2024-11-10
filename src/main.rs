use flexi_logger::*;
use mini_rust_desk_common::{bail, ResultType};
use mini_rust_desk_id_server::common::*;
use mini_rust_desk_id_server::RendezvousServer;
extern crate dotenvy;
use dotenvy::dotenv;

fn main() -> ResultType<()> {
    dotenv().ok();  
    let _logger = Logger::try_with_env_or_str("debug")?
        .log_to_stdout()
        //.log_to_file(flexi_logger::FileSpec::default()) 
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    let args = format!(
        "-p, --port=[NUMBER(default={RENDEZVOUS_PORT})] 'Sets the listening port'
        -R, --rendezvous-servers=[HOSTS] 'Sets rendezvous servers, separated by comma'
        -r, --relay-servers=[HOST] 'Sets the default relay servers, separated by comma'
        -k, --key=[KEY] 'Only allow the client with the same key'",
    );
    init_args(&args, "mini_rust_desk_id_server", "Mini RustDesk ID  Server");
    let port = get_arg_or("port", RENDEZVOUS_PORT.to_string()).parse::<i32>()?;
    if port < 3 {
        bail!("Invalid port");
    }
    RendezvousServer::start(port, &get_arg_or("key", "-".to_owned()), 0)?;
    Ok(())
}