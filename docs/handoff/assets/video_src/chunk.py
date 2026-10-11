import subprocess, sys, time
from scenes import frame, FPS, W, H
a, b, name = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
cmd = ["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(FPS),
       "-i", "-", "-c:v", "libx264", "-preset", "medium", "-crf", "18", "-pix_fmt", "yuv420p", name]
p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
t0 = time.time()
for i in range(a, b):
    p.stdin.write(frame(i / FPS).tobytes())
p.stdin.close(); p.wait()
print(name, "frames", a, b, round(time.time() - t0), "s")
