defmodule AwsEncryptionSdk.Crypto.HKDFTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Crypto.HKDF

  doctest AwsEncryptionSdk.Crypto.HKDF

  describe "hash_length/1" do
    test "returns 32 for sha256" do
      assert HKDF.hash_length(:sha256) == 32
    end

    test "returns 48 for sha384" do
      assert HKDF.hash_length(:sha384) == 48
    end

    test "returns 64 for sha512" do
      assert HKDF.hash_length(:sha512) == 64
    end
  end

  describe "RFC 5869 Test Case 1 (SHA-256 basic)" do
    # Test Case 1 from RFC 5869 Appendix A.1
    @ikm Base.decode16!("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
    @salt Base.decode16!("000102030405060708090A0B0C")
    @info Base.decode16!("F0F1F2F3F4F5F6F7F8F9")
    @length 42

    @expected_prk Base.decode16!(
                    "077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5"
                  )
    @expected_okm Base.decode16!(
                    "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865"
                  )

    test "extract/3 produces correct PRK" do
      prk = HKDF.extract(:sha256, @salt, @ikm)
      assert prk == @expected_prk
    end

    test "expand/4 produces correct OKM" do
      {:ok, okm} = HKDF.expand(:sha256, @expected_prk, @info, @length)
      assert okm == @expected_okm
    end

    test "derive/5 produces correct OKM (combined extract-then-expand)" do
      {:ok, okm} = HKDF.derive(:sha256, @ikm, @salt, @info, @length)
      assert okm == @expected_okm
    end
  end

  describe "RFC 5869 Test Case 2 (SHA-256 longer inputs)" do
    # Test Case 2 from RFC 5869 Appendix A.2
    # Tests longer inputs (80 bytes each) and output requiring 3 iterations
    @ikm Base.decode16!(
           "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"
         )
    @salt Base.decode16!(
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
          )
    @info Base.decode16!(
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
          )
    @length 82

    @expected_prk Base.decode16!(
                    "06A6B88C5853361A06104C9CEB35B45CEF760014904671014A193F40C15FC244"
                  )
    @expected_okm Base.decode16!(
                    "B11E398DC80327A1C8E7F78C596A49344F012EDA2D4EFAD8A050CC4C19AFA97C59045A99CAC7827271CB41C65E590E09DA3275600C2F09B8367793A9ACA3DB71CC30C58179EC3E87C14C01D5C1F3434F1D87"
                  )

    test "extract/3 produces correct PRK" do
      prk = HKDF.extract(:sha256, @salt, @ikm)
      assert prk == @expected_prk
    end

    test "expand/4 produces correct OKM (requires 3 iterations)" do
      {:ok, okm} = HKDF.expand(:sha256, @expected_prk, @info, @length)
      assert okm == @expected_okm
      # Verify length: 82 bytes requires ceil(82/32) = 3 iterations
      assert byte_size(okm) == 82
    end

    test "derive/5 produces correct OKM" do
      {:ok, okm} = HKDF.derive(:sha256, @ikm, @salt, @info, @length)
      assert okm == @expected_okm
    end
  end

  describe "RFC 5869 Test Case 3 (SHA-256 empty salt and info)" do
    # Test Case 3 from RFC 5869 Appendix A.3
    # Tests zero-length salt and info
    @ikm Base.decode16!("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
    @salt <<>>
    @info <<>>
    @length 42

    @expected_prk Base.decode16!(
                    "19EF24A32C717B167F33A91D6F648BDF96596776AFDB6377AC434C1C293CCB04"
                  )
    @expected_okm Base.decode16!(
                    "8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D9D201395FAA4B61A96C8"
                  )

    test "extract/3 with empty salt produces correct PRK" do
      prk = HKDF.extract(:sha256, @salt, @ikm)
      assert prk == @expected_prk
    end

    test "extract/3 with nil salt produces same PRK as empty salt" do
      prk_empty = HKDF.extract(:sha256, <<>>, @ikm)
      prk_nil = HKDF.extract(:sha256, nil, @ikm)
      assert prk_empty == prk_nil
      assert prk_empty == @expected_prk
    end

    test "expand/4 with empty info produces correct OKM" do
      {:ok, okm} = HKDF.expand(:sha256, @expected_prk, @info, @length)
      assert okm == @expected_okm
    end

    test "derive/5 with empty salt and info produces correct OKM" do
      {:ok, okm} = HKDF.derive(:sha256, @ikm, @salt, @info, @length)
      assert okm == @expected_okm
    end

    test "derive/5 with nil salt produces correct OKM" do
      {:ok, okm} = HKDF.derive(:sha256, @ikm, nil, @info, @length)
      assert okm == @expected_okm
    end
  end

  describe "SHA-512 support (Wycheproof vectors)" do
    # SHA-512 is critical for committed algorithm suites 0x0478 and 0x0578
    # Test vectors from Wycheproof hkdf_sha512_test.json

    test "tcId 1: empty salt, 20-byte output" do
      ikm = Base.decode16!("24AEFF2645E3E0F5494A9A102778C43A")
      expected_okm = Base.decode16!("DD2599840B09699C6200B5CBA79002B3AA75C61B")

      {:ok, okm} = HKDF.derive(:sha512, ikm, <<>>, <<>>, 20)
      assert okm == expected_okm
    end

    test "tcId 2: empty salt, 42-byte output" do
      ikm = Base.decode16!("A23632E18EC76B59B1C87008DA3F8A7E")

      expected_okm =
        Base.decode16!(
          "C4AF93D4BAE9CA2B45F590CD3D2F539FF5749D7B0864FBE44A438D38A2F8E5AFE01641145E389C989766"
        )

      {:ok, okm} = HKDF.derive(:sha512, ikm, <<>>, <<>>, 42)
      assert okm == expected_okm
    end

    test "tcId 3: empty salt, 64-byte output (single iteration max)" do
      ikm = Base.decode16!("A4748031A14D3E6AAFE42AA20C568F5F")

      expected_okm =
        Base.decode16!(
          "62EA97E06051E40B79DEB127A4DA294F557CAFA3D7A90A75C02064571DFBBE4699129BDCEC4B39EED7757CE8E3571589F7D8F5523C0DC3FD6A56B099FB4BFD51"
        )

      {:ok, okm} = HKDF.derive(:sha512, ikm, <<>>, <<>>, 64)
      assert okm == expected_okm
      # 64 bytes = exactly one SHA-512 iteration
      assert byte_size(okm) == HKDF.hash_length(:sha512)
    end

    test "extract/3 produces correct PRK length for SHA-512" do
      ikm = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(64)

      prk = HKDF.extract(:sha512, salt, ikm)
      assert byte_size(prk) == 64
    end
  end

  describe "SHA-384 support" do
    # SHA-384 is used by algorithm suites 0x0346 and 0x0378

    test "derive/5 produces correct output length" do
      ikm = :crypto.strong_rand_bytes(32)
      {:ok, okm} = HKDF.derive(:sha384, ikm, nil, <<>>, 32)
      assert byte_size(okm) == 32
    end

    test "extract/3 produces correct PRK length for SHA-384" do
      ikm = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(48)

      prk = HKDF.extract(:sha384, salt, ikm)
      assert byte_size(prk) == 48
    end

    test "expand/4 with multiple iterations" do
      prk = :crypto.strong_rand_bytes(48)
      # Request 100 bytes = ceil(100/48) = 3 iterations
      {:ok, okm} = HKDF.expand(:sha384, prk, "info", 100)
      assert byte_size(okm) == 100
    end
  end

  describe "edge cases" do
    test "expand/4 returns error when output length exceeds maximum" do
      prk = :crypto.strong_rand_bytes(32)

      # SHA-256 max: 255 * 32 = 8160
      assert {:error, :output_length_exceeded} = HKDF.expand(:sha256, prk, <<>>, 8161)

      # SHA-384 max: 255 * 48 = 12240
      prk384 = :crypto.strong_rand_bytes(48)
      assert {:error, :output_length_exceeded} = HKDF.expand(:sha384, prk384, <<>>, 12_241)

      # SHA-512 max: 255 * 64 = 16320
      prk512 = :crypto.strong_rand_bytes(64)
      assert {:error, :output_length_exceeded} = HKDF.expand(:sha512, prk512, <<>>, 16_321)
    end

    test "expand/4 succeeds at maximum output length" do
      prk = :crypto.strong_rand_bytes(32)

      # SHA-256 max: 255 * 32 = 8160
      assert {:ok, okm} = HKDF.expand(:sha256, prk, <<>>, 8160)
      assert byte_size(okm) == 8160
    end

    test "expand/4 with zero length returns empty binary" do
      prk = :crypto.strong_rand_bytes(32)
      assert {:ok, <<>>} = HKDF.expand(:sha256, prk, <<>>, 0)
    end

    test "derive/5 returns error when output length exceeds maximum" do
      ikm = :crypto.strong_rand_bytes(32)
      assert {:error, :output_length_exceeded} = HKDF.derive(:sha256, ikm, nil, <<>>, 8161)
    end

    test "derive/5 with zero length returns empty binary" do
      ikm = :crypto.strong_rand_bytes(32)
      assert {:ok, <<>>} = HKDF.derive(:sha256, ikm, nil, <<>>, 0)
    end

    test "extract/3 with empty IKM succeeds" do
      # RFC 5869 doesn't prohibit empty IKM
      prk = HKDF.extract(:sha256, nil, <<>>)
      assert byte_size(prk) == 32
    end
  end

  describe "algorithm suite compatibility" do
    # Verify HKDF works with parameters from actual algorithm suites

    test "works with suite 0x0578 parameters (SHA-512, 32-byte input)" do
      # AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
      ikm = :crypto.strong_rand_bytes(32)
      message_id = :crypto.strong_rand_bytes(32)

      {:ok, data_key} = HKDF.derive(:sha512, ikm, message_id, "DERIVEKEY", 32)
      {:ok, commit_key} = HKDF.derive(:sha512, ikm, message_id, "COMMITKEY", 32)

      assert byte_size(data_key) == 32
      assert byte_size(commit_key) == 32
      # Keys should be different due to different info
      assert data_key != commit_key
    end

    test "works with suite 0x0178 parameters (SHA-256, 32-byte input)" do
      # AES_256_GCM_IV12_TAG16_HKDF_SHA256
      ikm = :crypto.strong_rand_bytes(32)
      message_id = :crypto.strong_rand_bytes(16)
      # Non-committed suites use algorithm_id || message_id as info
      info = <<0x01, 0x78, message_id::binary>>

      {:ok, data_key} = HKDF.derive(:sha256, ikm, nil, info, 32)
      assert byte_size(data_key) == 32
    end

    test "works with suite 0x0346 parameters (SHA-384, 24-byte input)" do
      # AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
      ikm = :crypto.strong_rand_bytes(24)
      message_id = :crypto.strong_rand_bytes(16)
      info = <<0x03, 0x46, message_id::binary>>

      {:ok, data_key} = HKDF.derive(:sha384, ikm, nil, info, 24)
      assert byte_size(data_key) == 24
    end
  end
end
