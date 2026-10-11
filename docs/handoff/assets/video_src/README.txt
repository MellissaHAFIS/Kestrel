Regenerate the video (needs Python, Pillow, numpy, ffmpeg):
  python3 audio.py                         # writes audio.wav
  copy scenes_en.py (or scenes_fr.py) to scenes.py
  python3 chunk.py 0 664 seg_0.mp4
  python3 chunk.py 664 1328 seg_1.mp4
  python3 chunk.py 1328 1992 seg_2.mp4
  printf "file 'seg_0.mp4'\nfile 'seg_1.mp4'\nfile 'seg_2.mp4'\n" > list.txt
  ffmpeg -f concat -safe 0 -i list.txt -i audio.wav -c:v copy -c:a aac -shortest out.mp4
