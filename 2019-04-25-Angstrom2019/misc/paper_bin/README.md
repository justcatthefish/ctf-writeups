# Paper Bin (40 points, 372 solves)
We were given an almost 8MB file to dig into it. First thing that came to my mind was to run binwalk on the file and try to extract files with known magic bytes. Binwalk found many files however many of them were corrupted. Since it found also pdf magic bytes I tried my luck with foremost, to recover any valid pdf:
```foremost -i paper_bin.dat -t pdf```

It found 20 valid pdfs. I found the flag in one of them:
```actf{proof_by_triviality}```

