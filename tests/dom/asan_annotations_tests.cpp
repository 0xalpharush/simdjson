// Under AddressSanitizer, the DOM parser poisons the bytes that follow each
// parsed string in the string buffer, and the unused part of the tape (see
// SIMDJSON_ASAN_ANNOTATIONS). These tests check the poisoned layout, and that
// valid uses (parser reuse, document streams) do not trip it.

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "simdjson.h"
#include "test_macros.h"

#if SIMDJSON_ASAN_ANNOTATIONS
extern "C" int __asan_address_is_poisoned(void const volatile *addr);

namespace asan_annotations_tests {
using namespace simdjson;

// The NUL terminator is addressable, the byte after it is poisoned.
bool check_string(std::string_view s) {
  ASSERT_TRUE(!__asan_address_is_poisoned(s.data() + s.size()));
  ASSERT_TRUE(__asan_address_is_poisoned(s.data() + s.size() + 1));
  return true;
}

bool string_redzones() {
  TEST_START();
  dom::parser parser;
  // String lengths 0 to 17 so that string ends hit every offset in a granule.
  std::string json = "[";
  for (size_t i = 0; i < 18; i++) {
    json += (i ? ",\"" : "\"") + std::string(i, 'a') + "\"";
  }
  json += ",{\"key\":\"value\"}]";
  dom::array array;
  ASSERT_SUCCESS(parser.parse(json).get(array));
  size_t count = 0;
  for (dom::element e : array) {
    std::string_view s;
    if (e.is_string()) {
      ASSERT_SUCCESS(e.get(s));
      ASSERT_EQUAL(s.size(), count);
      if (!check_string(s)) { return false; }
      count++;
    } else if (e.is_object()) {
      for (dom::key_value_pair field : dom::object(e)) {
        if (!check_string(field.key)) { return false; }
        ASSERT_SUCCESS(field.value.get(s));
        if (!check_string(s)) { return false; }
      }
    }
  }
  ASSERT_EQUAL(count, size_t(18));
  TEST_SUCCEED();
}

bool big_integer_redzone() {
  TEST_START();
  dom::parser parser;
  parser.number_as_string(true);
  dom::element e;
  ASSERT_SUCCESS(parser.parse("[123456789012345678901234567890]"_padded).get(e));
  std::string_view s;
  ASSERT_SUCCESS(e.at(0).get_bigint().get(s));
  if (!check_string(s)) { return false; }
  TEST_SUCCEED();
}

bool tape_tail() {
  TEST_START();
  dom::parser parser;
  dom::element e;
  ASSERT_SUCCESS(parser.parse(R"({"a":[1,2,3]})"_padded).get(e));
  // The root element holds the number of tape words used.
  size_t used = size_t(parser.doc.tape[0] & 0x00FFFFFFFFFFFFFFull);
  ASSERT_TRUE(!__asan_address_is_poisoned(&parser.doc.tape[used - 1]));
  ASSERT_TRUE(__asan_address_is_poisoned(&parser.doc.tape[used]));
  TEST_SUCCEED();
}

bool parser_reuse() {
  TEST_START();
  dom::parser parser;
  dom::element e;
  ASSERT_SUCCESS(parser.parse(R"(["a","b","c","d","e","f"])"_padded).get(e));
  // The second document writes over the redzones of the first one.
  std::string_view s;
  ASSERT_SUCCESS(parser.parse(R"(["abcdefghijklmnopqrstuvwxyz"])"_padded).get(e));
  ASSERT_SUCCESS(e.at(0).get(s));
  ASSERT_EQUAL(s, "abcdefghijklmnopqrstuvwxyz");
  if (!check_string(s)) { return false; }
  TEST_SUCCEED();
}

bool last_document_of_stream() {
  TEST_START();
  dom::parser parser;
  dom::document_stream stream;
  auto json = R"("a" "bc" "def")"_padded;
  ASSERT_SUCCESS(parser.parse_many(json).get(stream));
  std::string_view last;
  for (auto doc : stream) {
    ASSERT_SUCCESS(doc.get(last));
  }
  // The stream runs stage 2 once more at the end; the last string stays valid.
  ASSERT_EQUAL(last, "def");
  TEST_SUCCEED();
}

bool run() {
  return string_redzones() && big_integer_redzone() && tape_tail() &&
         parser_reuse() && last_document_of_stream();
}
} // namespace asan_annotations_tests

int main() {
  std::cout << "Running AddressSanitizer annotation tests." << std::endl;
  if (asan_annotations_tests::run()) {
    std::cout << "AddressSanitizer annotation tests are ok." << std::endl;
    return EXIT_SUCCESS;
  }
  return EXIT_FAILURE;
}
#else
int main() {
  std::cout << "AddressSanitizer annotations are disabled: skipping." << std::endl;
  return EXIT_SUCCESS;
}
#endif
