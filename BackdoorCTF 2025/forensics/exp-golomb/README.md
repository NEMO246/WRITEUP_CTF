## BackdoorCTF 2025 - exp-golomb Write-up

![Challenge Info](images/1.png)

### Step 1: Identification & Codec Analysis

I was given a raw video file (`video_raw.hevc`) and a directory `nal_units` containing subdirectories `A`, `B`, and `C`. To understand what I was dealing with, I inspected the contents of the header files using `strings`.

```bash
strings nal_units/*/*
```

The output provided a crucial clue: `Nx265 (build 199) ... H.265/HEVC codec`.
This confirmed that the files were NAL units for an **H.265 (HEVC)** video stream. However, the `strings` output also revealed that many of these "header" files contained readable text (likely decoys) rather than the expected binary data required for video decoding.

### Step 2: Isolating Valid NAL Units

To decode the raw HEVC stream, I needed the specific Parameter Sets: **VPS** (Video Parameter Set), **SPS** (Sequence Parameter Set), and **PPS** (Picture Parameter Set).

Since I knew from Step 1 that many files were text-based decoys, I checked the file sizes to identify the legitimate binary headers.

```bash
ls -l nal_units/*/*
```

![File Listing](images/1.png)

**Key Observations:**
*   Most files (`A/a.hed`, `A/c.hed`, `B/b.hed`, etc.) are exactly **54 bytes**. These correspond to the text files I saw in `strings` and are invalid for decoding.
*   Three files have unique sizes, making them the valid binary headers:
    1.  `nal_units/C/c.hed`: **28 bytes** (VPS).
    2.  `nal_units/A/b.hed`: **47 bytes** (SPS).
    3.  `nal_units/B/a.hed`: **15034 bytes** (PPS).

### Step 3: Stream Reconstruction

I reconstructed the functional video stream by concatenating the valid headers in the standard HEVC order (`VPS` -> `SPS` -> `PPS`) followed by the raw video data.

```bash
cat nal_units/C/c.hed nal_units/A/b.hed nal_units/B/a.hed video_raw.hevc > flag.hevc
```

![Reconstruction Command](images/2.png)

Next, I wrapped the raw HEVC stream into an MP4 container using `ffmpeg`. The absence of decoding errors confirmed that I had selected the correct headers.

```bash
ffmpeg -i flag.hevc -c copy flag.mp4
```

![FFmpeg Conversion](images/3.png)

### Step 4: Extracting the Flag

I verified that the output file was a valid MP4 container. But it couldn't be opened.

![File Verify](images/4.png)

So, I extracted frames from the video to read the flag.

```bash
ffmpeg -i flag.mp4 frame%03d.png
```

![Frame Extraction](images/5.png)

Opening the extracted frame reveals a test pattern with the flag scrolling across it.

![Flag Frame](images/frame001.png)

The text on the screen reads: `[h265_3nc0d1ng_1s_r34lly_g00d_f0r_4K_v1d]`

### Flag
`flag{h265_3nc0d1ng_1s_r34lly_g00d_f0r_4K_v1d}`