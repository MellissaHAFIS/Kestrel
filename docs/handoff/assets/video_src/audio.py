import numpy as np, wave
SR = 44100
DUR = 83.0
N = int(SR * DUR)
rng = np.random.default_rng(7)
L = np.zeros(N); R = np.zeros(N)

def add(sig, t0, pan=0.0, gain=1.0):
    i = int(t0 * SR)
    if i < 0:
        sig = sig[-i:]
        i = 0
    if i >= N or len(sig) == 0: return
    n = min(len(sig), N - i)
    L[i:i+n] += sig[:n] * gain * (1 - max(0, pan)) 
    R[i:i+n] += sig[:n] * gain * (1 + min(0, pan))

def tt(d): return np.arange(int(SR * d)) / SR

def smooth(x, k):
    return np.convolve(x, np.ones(k) / k, mode="same")

# ---------- pad ----------
chords = [[110.0, 164.81, 220.0, 261.63], [87.31, 130.81, 174.61, 220.0],
          [130.81, 196.0, 261.63, 329.63], [98.0, 146.83, 196.0, 246.94]]
seg = 8.0
for i in range(-1, int(DUR / seg) + 1):
    ch = chords[i % 4]
    d = seg + 3.0
    t = tt(d)
    env = np.sin(np.pi * np.clip(t / d, 0, 1)) ** 2
    sig = np.zeros_like(t)
    for f in ch:
        sig += 0.5 * np.sin(2*np.pi*f*t) + 0.25 * np.sin(2*np.pi*f*1.004*t) + 0.10 * np.sin(2*np.pi*2*f*t)
    sig *= env * 0.045 * (1 + 0.12 * np.sin(2*np.pi*0.23*t))
    add(sig, i * seg - 1.0)
# soft pulse (heartbeat-like sub) for tension
for k in np.arange(0, DUR, 2.0):
    t = tt(0.5)
    add(np.sin(2*np.pi*48*t) * np.exp(-t * 9) * 0.10, k)

# ---------- sfx ----------
def ping(f, t0, g=0.22, pan=0.0, d=0.7):
    t = tt(d)
    s = (np.sin(2*np.pi*f*t) + 0.35*np.sin(2*np.pi*2*f*t)) * np.exp(-t * 7)
    add(s, t0, pan, g)

def pop(t0, g=0.18):
    t = tt(0.25)
    f = 380 + 260 * np.exp(-t * 30)
    add(np.sin(2*np.pi*np.cumsum(f)/SR) * np.exp(-t * 16), t0, 0, g)

def thud(t0, g=0.55):
    t = tt(0.8)
    f = 135 * np.exp(-t * 6) + 42
    s = np.sin(2*np.pi*np.cumsum(f)/SR) * np.exp(-t * 6.5)
    nz = smooth(rng.standard_normal(len(t)), 40) * np.exp(-t * 18) * 3
    add(s + nz * 0.5, t0, 0, g)

def whoosh(t0, d=1.4, g=0.28):
    t = tt(d)
    env = np.sin(np.pi * np.clip(t / d, 0, 1)) ** 2
    nz = rng.standard_normal(len(t))
    k = 8
    out = smooth(nz, k) * env
    out = np.convolve(out, np.ones(60) / 60, mode="same") * 6
    add(out, t0, 0, g)

def alert(t0, g=0.2):
    for j, f in enumerate([740, 554]):
        t = tt(0.16)
        add(np.sign(np.sin(2*np.pi*f*t)) * 0.4 * np.sin(2*np.pi*f*t) * np.exp(-t * 10) , t0 + j * 0.18, 0, g * 2)

def alarm(t0, g=0.35):
    thud(t0, g)
    for j, f in enumerate([880, 660, 880, 660]):
        t = tt(0.22)
        s = np.sin(2*np.pi*f*t) * np.exp(-t * 6)
        add(s, t0 + 0.08 + j * 0.24, 0, 0.2)

def boom(t0, g=0.5):
    t = tt(2.2)
    f = 60 * np.exp(-t * 0.8) + 36
    s = np.sin(2*np.pi*np.cumsum(f)/SR) * np.exp(-t * 2.2)
    rise = np.sin(2*np.pi*np.cumsum(180 + 600 * (t / 2.2)) / SR) * (t / 2.2) ** 3 * np.exp(-t * 0.6) * 0.15
    add(s * 1.2 + rise, t0, 0, g)
    for f in (880, 1320, 1760):
        ping(f, t0 + 0.3, 0.07, 0, 1.6)

def chime(t0, g=0.25):
    t = tt(3.0)
    s = sum(np.sin(2*np.pi*f*t) * np.exp(-t * 1.6) for f in (523.25, 659.25, 783.99, 1046.5))
    add(s, t0, 0, g * 0.5)

whoosh(8.1, 1.4)
alert(9.3)
for i, t0 in enumerate([12.0, 13.6, 15.2]):
    pop(t0); ping(1175, t0 + 0.55, 0.16)
alarm(17.0)
boom(24.0)
for i, t0 in enumerate([33.9, 34.4, 34.9]):
    ping(1175 + 150 * i, t0, 0.2)
for i, t0 in enumerate([36.8]):
    whoosh(t0, 1.2, 0.18)
for i, f in enumerate([880, 988, 1175, 1319]):
    ping(f, 38.9 + i * 1.6, 0.22)
for i in range(4):
    pop(45.6 + i * 0.25, 0.12)
thud(47.0, 0.5)
ping(1319, 48.1, 0.2)
for t0 in (51.2, 52.4, 53.6):
    pop(t0, 0.07)
thud(52.0, 0.35)
alert(53.2)
ping(1175, 55.8, 0.2)
for i in range(3):
    pop(62.5 + i * .25, 0.08)
pop(63.6, 0.1); pop(63.8, 0.1); pop(64.0, 0.1)
ping(1568, 64.6, 0.2)
for i in range(4):
    pop(70.2 + i * 0.7, 0.07)
chime(79.5)

# ---------- master ----------
t = np.arange(N) / SR
fade = np.clip(t / 2.0, 0, 1) * np.clip((DUR - t) / 3.0, 0, 1)
L *= fade; R *= fade
peak = max(np.abs(L).max(), np.abs(R).max())
L = L / peak * 0.8; R = R / peak * 0.8
st = (np.stack([L, R], axis=1) * 32767).astype(np.int16)
with wave.open("audio.wav", "wb") as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR); w.writeframes(st.tobytes())
print("audio ok", st.shape)
