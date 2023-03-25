use std::collections::HashSet;
use std::hash::Hash;

/// just deuplicates a vector
pub fn dedup<T: Eq + Hash + Copy>(v: &mut Vec<T>) {
    let mut uniques = HashSet::new();
    v.retain(|e| uniques.insert(*e));
}
