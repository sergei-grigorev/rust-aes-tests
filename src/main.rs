use log;

mod certs;
mod password;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match password::generate_password() {
        Ok(mut pass) => {
            if let Err(e) = certs::create_cert(&mut pass) {
                log::error!("AES generation failed: {}", e);
                todo!()
            } else {
                Ok(())
            }
        }
        Err(e) => {
            log::error!("Master password was not received: {}", e);
            todo!()
        }
    }
}
