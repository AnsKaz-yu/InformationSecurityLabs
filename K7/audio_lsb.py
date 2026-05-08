import wave


def to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def from_bits(bits: str) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if len(chunk) == 8:
            out.append(int(chunk, 2))
    return bytes(out)


def max_payload_bytes(audio_path: str) -> int:
    with wave.open(audio_path, "rb") as audio:
        frame_bytes = audio.readframes(audio.getnframes())
    return max((len(frame_bytes) - 32) // 8, 0)


def encode_lsb_audio(audio_path: str, message: str, output_path: str) -> None:
    with wave.open(audio_path, "rb") as audio:
        params = audio.getparams()
        frame_bytes = bytearray(audio.readframes(audio.getnframes()))

    payload = message.encode("utf-8")
    header = len(payload).to_bytes(4, byteorder="big")
    bits = to_bits(header + payload)

    if len(bits) > len(frame_bytes):
        raise ValueError("Message is too large for this audio file")

    for i, bit in enumerate(bits):
        frame_bytes[i] = (frame_bytes[i] & 0xFE) | int(bit)

    with wave.open(output_path, "wb") as encoded:
        encoded.setparams(params)
        encoded.writeframes(bytes(frame_bytes))


def decode_lsb_audio(audio_path: str) -> str:
    with wave.open(audio_path, "rb") as audio:
        frame_bytes = audio.readframes(audio.getnframes())

    header_bits = "".join(str(frame_bytes[i] & 1) for i in range(32))
    message_len = int.from_bytes(from_bits(header_bits), byteorder="big")

    total_message_bits = message_len * 8
    message_bits = "".join(str(frame_bytes[i] & 1) for i in range(32, 32 + total_message_bits))
    return from_bits(message_bits).decode("utf-8", errors="strict")


def main() -> None:
    audio_path = "K7/original.wav"
    output_path = "K7/encoded.wav"
    message = "Секретное сообщение в аудиофайле K7"

    print(f"\n=== K7: Audio LSB ===")
    print(f"Capacity (bytes): {max_payload_bytes(audio_path)}")
    encode_lsb_audio(audio_path, message, output_path)
    print(f"Encoded successfully: {output_path}")

    decoded = decode_lsb_audio(output_path)
    print(f"Decoded message: {decoded}")
    print()


if __name__ == "__main__":
    main()
