fn main() {
    // `sqlx::migrate!` embeds the migrations at compile time, so new files must trigger a rebuild.
    println!("cargo:rerun-if-changed=migrations");
}
