# Paper Bin (40 points, 372 solves)
We were given an almost 8Mb files to dig into. First thing that came to my mind was to run binwalk on the file and try to extract files with known magic bytes. Binwalk found many files however many of them were corrupted. Since it found also pdf magic bytes I tried my luck with foremost, to recover all pdfs:
```foremost -i paper_bin.dat -t pdf```

It found 20 valid pdfs. After viewing all of them I found the flag:
```actf{proof_by_triviality}```

