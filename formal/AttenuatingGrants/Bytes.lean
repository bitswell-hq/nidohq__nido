/-!
# Byte strings

Every identifier in the vocabularies (contract ids, function names, wasm
hashes, hosts, key ids, network ids, path components) is a byte string,
compared by exact bytewise equality. Normalization (host lowercasing, path
canonicalization, DNS) happens in host wiring before an action reaches the
evaluator, so it is not modelled here.

Byte strings are `List UInt8`: Aeneas translates a Rust `Vec<u8>` or `&[u8]`
to a structure whose `val` projection is a `List` of bytes, so an equivalence
proof relates the two by that projection.
-/

namespace AttenuatingGrants

/-- A byte string, compared bytewise by the derived `DecidableEq`. -/
abbrev Bytes := List UInt8

/-- The UTF-8 bytes of a string literal, for writing examples. -/
def Bytes.ofString (s : String) : Bytes := s.toUTF8.toList

end AttenuatingGrants
