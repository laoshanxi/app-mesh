use anyhow::{bail, Context, Result};

use crate::app::{Cli, GetArgs, PutArgs, RmfileArgs};
use crate::client::build_client_with_auth;
use crate::output::format::human_readable_size;

pub async fn get(cli: &Cli, args: &GetArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    client
        .download_file(&args.remote, &args.local, args.apply_permissions && !args.no_attr)
        .await
        .context("Download failed")?;

    let file_size = std::fs::metadata(&args.local).map(|m| m.len()).unwrap_or(0);

    eprintln!("Download remote file <{}> to local <{}> size <{}>", args.remote, args.local, human_readable_size(file_size));
    Ok(0)
}

pub async fn put(cli: &Cli, args: &PutArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    let local_path = std::path::Path::new(&args.local);
    if !local_path.exists() {
        bail!("Local file not found: {}", args.local);
    }

    let local_canonical = std::fs::canonicalize(local_path).unwrap_or_else(|_| local_path.to_path_buf());

    client
        .upload_file_with(
            &local_canonical.to_string_lossy(),
            &args.remote,
            args.apply_permissions && !args.no_attr,
            args.overwrite,
        )
        .await
        .context("Upload failed")?;

    eprintln!("Uploaded: {} -> {}", args.local, args.remote);
    Ok(0)
}

pub async fn rmfile(cli: &Cli, args: &RmfileArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    client.delete_file(&args.remote).await.context("File removal failed")?;

    eprintln!("Removed remote file <{}>", args.remote);
    Ok(0)
}
