#ifndef MNEMONIC_HPP
#define MNEMONIC_HPP

#include <cstdint>

#include <vector>

#include <string>
#include <string_view>

#include <iostream>

#include "words.hpp"
#include "sha256.hpp"
#include "bit_opts.hpp"

namespace bip39 {

class Mnemonic {
public:
    Mnemonic(std::vector<uint8_t> entropy, std::string lang, WordListLoader& loader)
        : entropy_(std::move(entropy))
        , lang_(std::move(lang))
        , num_bits_(entropy_.size() * 8)
        , word_list_loader_(loader)
    {
        auto data = entropy_;
        SHA256 sha;
        sha.Update(data.data(), data.size());
        auto const& sha_res = sha.GetResult();
        int num_check_sum = num_bits_ / 32;
        uint8_t check_sum = sha_res[0] & (Bits::MakeMask(num_check_sum));
        data.push_back(check_sum);
        auto word_list = word_list_loader_.Load(lang_);
        int total_bits = num_bits_ + num_check_sum;
        assert(total_bits % 11 == 0);
        int num_words = total_bits / 11;
        Bits bits(data, total_bits);
        for (int i = 0; i < num_words; ++i) {
            int word_index = bits.FrontBitsToUInt16(11);
            word_list_.push_back(word_list[word_index]);
            bits.ShiftToLeft(11);
        }
    }

    Mnemonic(WordList const& word_list, std::string lang, WordListLoader& loader)
        : word_list_loader_(loader)
        , lang_(std::move(lang))
    {
        if (word_list.size() % 3 != 0) {
            throw std::runtime_error("invalid number of words to convert");
        }
        Bits bits;
        auto words = loader.Load(lang_);
        for (auto const& word : word_list) {
            auto it = std::find(std::cbegin(words), std::cend(words), word);
            if (it != std::cend(words)) {
                uint16_t index = std::distance(std::cbegin(words), it);
                bits.AddBits(11, index);
            }
        }
        int num_ent_bits = word_list.size() * 32 / 3;
        int num_entropy_bytes = num_ent_bits / 8;
        entropy_.resize(num_entropy_bytes);
        std::copy(std::cbegin(bits.GetData()), std::cbegin(bits.GetData()) + num_entropy_bytes, std::begin(entropy_));
    }

    WordList const& GetWordList() const
    {
        return word_list_;
    }

    std::vector<uint8_t> const& GetEntropyData() const
    {
        return entropy_;
    }

    std::vector<uint8_t> CreateSeed(std::string_view passphrase)
    {
        std::string salt = std::string(u8"mnemonic") + std::string(passphrase);
        int const out_len{512 / 8};
        std::vector<uint8_t> out(out_len);
        std::string words = GenerateWords(word_list_, GetDelimiterByLang(lang_));
        int res = PKCS5_PBKDF2_HMAC(words.data(), words.size(), reinterpret_cast<uint8_t const*>(salt.data()), salt.size(), 2048, EVP_sha512(), out_len, out.data());
        if (1 != res) {
            throw std::runtime_error("failed to run algorithm: PBKDF2");
        }
        return out;
    }

private:
    std::vector<uint8_t> entropy_;
    std::string lang_;
    int num_bits_;
    WordListLoader& word_list_loader_;
    mutable WordList word_list_;
};

} // namespace bip39

#endif
