#include "toolbox.h"

#include <fstream>
#include <sstream>

namespace bip39 {

uint8_t CharToInt(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    } else if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 0x0a;
    }
    throw std::runtime_error("invalid hex char");
}

std::vector<uint8_t> ParseHex(std::string_view hex)
{
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("invalid length of the incoming hex string");
    }
    std::vector<uint8_t> res;
    std::string str{hex};
    uint8_t val{0};
    bool paired{false};
    for (auto i = std::begin(str); i != std::end(str); ++i) {
        *i = std::tolower(*i);
        val += CharToInt(*i);
        if (paired) {
            res.push_back(val);
            val = 0;
            paired = false;
        } else {
            val <<= 4;
            paired = true;
        }
    }
    return res;
}

std::vector<std::string> ParseWords(std::string_view words, std::string_view delimiter)
{
    std::vector<std::string> res;
    int p{0};
    int f = words.find(delimiter);
    while (f != std::string_view::npos) {
        res.push_back(std::string(words.substr(p, f - p)));
        p = f + delimiter.size();
        f = words.find(delimiter, p);
    }
    res.push_back(std::string(words.substr(p)));
    return res;
}

std::string GenerateWords(std::vector<std::string> const& word_list, std::string_view delimiter)
{
    std::stringstream ss;
    bool first{true};
    for (auto const& word : word_list) {
        if (first) {
            ss << word;
            first = false;
        } else {
            ss << delimiter << word;
        }
    }
    return ss.str();
}

std::string GetDelimiterByLang(std::string_view lang)
{
    if (lang == "japanese") {
            return "\xe3\x80\x80"; // UTF-8 encoding of U+3000 (ideographic space)
        } else {
            return " ";
        }
}

} // namespace bip39
