use std::path::PathBuf;
use std::borrow::Cow;
use separator::Separatable;
use walkdir::WalkDir;

struct EncodedPath {
    original_path: PathBuf,
    encoded_path: String,
}

fn main() {
    let start_dir = if std::env::args().len() > 1 {
        PathBuf::from(std::env::args().nth(1).unwrap())
    } else {
        std::env::current_dir().expect("Could not determine current directory.")
    };

    println!("Counting paths below {} according to encoding needs.", start_dir.display());

    let mut total_paths = 0;
    let mut num_not_encoded = 0;
    let mut num_encoded = 0;
    let mut encoded_paths = Vec::new();

    // Recursively walk from start_dir, ignoring any errors (which occur for
    // such things as 'permission denied'.
    for entry in WalkDir::new(start_dir).into_iter().filter_map(|e| e.ok()) {
        total_paths += 1;
        let pb = entry.into_path();
        let possibly_encoded_path = paths_as_strings::encode_path(&pb);

        match possibly_encoded_path {
            Cow::Borrowed(_s) => num_not_encoded += 1,
            Cow::Owned(encoded_path) => {
                num_encoded += 1;
                let round_tripped = paths_as_strings::decode_path(&encoded_path)
                    .expect("Decoding the encoded string should always work in this program.");
                println!("  Found a path requiring encoding : {:?}", pb);
                println!("  Encoded form is                 : {:?}", encoded_path);
                // println!("  Round tripped back to path is   : {:?}", round_tripped);
                // Assert here, so the program will stop with the offender as the last thing printed.
                // Of course, this assert should always succeed.
                assert_eq!(pb, round_tripped);

                // Accumulate these for printing them all at the end.
                let pre = EncodedPath { original_path: pb.clone(), encoded_path };
                encoded_paths.push(pre);
            }
        }

        if total_paths % 1000 == 0 {
            print_msg(num_not_encoded, num_encoded);
        }
    }

    println!("\nCounting complete. Totals follow:");
    print_msg(num_not_encoded, num_encoded);


    if num_encoded > 0 {
        let percentage = 100f64 * num_encoded as f64 / f64::from(total_paths);

        println!("\n{} out of {} paths needed encoding (and were successfully round-tripped).",
                 num_encoded, total_paths.separated_string());
        println!("This represents {}% of the total path count.\n", percentage);

        // for ep in encoded_paths {
        //     println!("Original path: {:?}", ep.original_path);
        //     println!("Encoded form : {:?}", ep.encoded_path);
        // }
    }
}

fn print_msg(num_not_encoded: usize, num_encoded: usize) {
    println!("num_not_encoded = {}, num_encoded = {}", num_not_encoded, num_encoded);
}
