import cv2

MAGIC = b"LSB1"
HEADER_SIZE_BYTES = 8  # 4 bytes magic + 4 bytes payload length


def to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def from_bits(bits: str) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if len(chunk) == 8:
            out.append(int(chunk, 2))
    return bytes(out)


def open_capture(video_path: str):
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {video_path}")

    return cap


def read_video_info(video_path: str):
    cap = open_capture(video_path)

    fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    cap.release()

    if width <= 0 or height <= 0:
        raise ValueError("Invalid video dimensions")
    if frame_count <= 0:
        raise ValueError("Cannot determine frame count")

    return fps, width, height, frame_count


def iter_lsb_bits(video_path: str):
    cap = open_capture(video_path)
    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            flat = frame.reshape(-1)
            for value in flat:
                yield int(value) & 1
    finally:
        cap.release()


def create_writer(output_path: str, fps: float, width: int, height: int):
    for codec in ["HFYU", "DIB ", "FFV1"]:
        fourcc = cv2.VideoWriter_fourcc(*codec)
        writer = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        if writer.isOpened():
            return writer, codec
    raise ValueError("Cannot open output video writer with supported lossless codecs")



def max_payload_bytes(video_path: str) -> int:
    _, width, height, frame_count = read_video_info(video_path)
    capacity_bits = frame_count * width * height * 3
    return max((capacity_bits // 8) - HEADER_SIZE_BYTES, 0)


def encode_lsb_video(video_path: str, message: str, output_path: str) -> None:
    fps, width, height, frame_count = read_video_info(video_path)

    payload = message.encode("utf-8")
    header = MAGIC + len(payload).to_bytes(4, byteorder="big")
    bits = to_bits(header + payload)

    capacity_bits = frame_count * width * height * 3
    if len(bits) > capacity_bits:
        raise ValueError("Message is too large for this video")

    cap = open_capture(video_path)
    writer, used_codec = create_writer(output_path, fps, width, height)

    bit_index = 0
    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                break

            flat = frame.reshape(-1)
            if bit_index < len(bits):
                writable = min(len(flat), len(bits) - bit_index)
                for i in range(writable):
                    flat[i] = (flat[i] & 0xFE) | int(bits[bit_index])
                    bit_index += 1

            writer.write(frame)
    finally:
        cap.release()
        writer.release()

    if bit_index < len(bits):
        raise ValueError("Failed to encode full message into output video")

    print(f"Codec used: {used_codec}")


def decode_lsb_video(video_path: str) -> str:
    capacity = max_payload_bytes(video_path)
    bits_iter = iter_lsb_bits(video_path)

    header_bits = "".join(str(next(bits_iter)) for _ in range(HEADER_SIZE_BYTES * 8))
    header = from_bits(header_bits)

    if len(header) != HEADER_SIZE_BYTES or header[:4] != MAGIC:
        raise ValueError("Invalid LSB header. The video is not encoded by this script or was recompressed")

    message_len = int.from_bytes(header[4:], byteorder="big")
    if message_len < 0 or message_len > capacity:
        raise ValueError("Invalid message length in header. The video may be damaged or lossy-compressed")

    message_bytes = bytearray()
    for _ in range(message_len):
        byte_bits = "".join(str(next(bits_iter)) for _ in range(8))
        message_bytes.append(int(byte_bits, 2))

    return message_bytes.decode("utf-8", errors="strict")


def main() -> None:
    try:
        video_path = "K8/original.avi"
        output_path = "K8/encoded.avi"
        message = "Видеостеганография K8: скрытое сообщение"

        print(f"\n=== K8: Video LSB ===")
        print(f"Capacity (bytes): {max_payload_bytes(video_path)}")
        encode_lsb_video(video_path, message, output_path)
        print(f"Encoded successfully: {output_path}")

        decoded = decode_lsb_video(output_path)
        print(f"Decoded message: {decoded}")
    except FileNotFoundError:
        print(f"\n=== K8: Video LSB ===")
        print(f"Error: Video file not found at Steganografy/K8/video/original.avi")
        print(f"To run: provide .avi file with lossless codec (FFV1) to avoid LSB corruption")
    except Exception as e:
        print(f"\n=== K8: Video LSB ===")
        print(f"Error: {type(e).__name__}: {e}")
    

if __name__ == "__main__":
    main()
