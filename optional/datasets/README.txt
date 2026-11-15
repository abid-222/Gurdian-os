PUT YOUR DATASET HERE, THEN PRESS "Train model now" IN GUARDIAN > Model Lab.

You do not have to rename or unzip anything. Guardian unpacks zips by itself.

Option 1 - EMBER2024 (recommended, real labelled data, 2568 features)
  Download from https://huggingface.co/datasets/joyce8/EMBER2024  ->  e.g. Win64_test.zip (1.2 GB) [and Win64_train.zip (5.9 GB) if you want a bigger model]
  Drop the zip(s) into this folder (or into datasets/ember2024/).
  Only the Win32 / Win64 / .NET files are used. One zip is enough: it is split by time (first 60% train, next 15% validation, last 25% test).
  The number of rows used is capped automatically to fit your PC's RAM (default 150,000).

Option 2 - your own files
  datasets/benign/    clean .exe / .dll files (e.g. copied from C:\Windows\System32 and C:\Program Files)
  datasets/malware/   malware samples (a zip with the usual password "infected" also works)
  Use a few hundred files per class at least. Samples are only parsed, never executed. Do this only on a machine/VM you are prepared to handle malware on.

Option 3 - a CSV
  A table of PE header fields with a label column (label / class / malware / legitimate ...), e.g. the common Kaggle "malware dataset" CSVs.
  Only columns Guardian can recompute from a real .exe are used (Machine, SizeOfCode, SectionsMeanEntropy, ImportsNb ...); the rest are ignored.
  A CSV of other things (hashes, behaviour logs, network flows) cannot be used by the live file scanner and will be reported as "not usable".

Quality gate: after training, the model is only used as evidence when its test ROC-AUC is >= 0.85 and the test false-positive rate at the alert threshold is <= 2%.
Otherwise it is kept for inspection and Model Lab says why. Random-split CSV/folder results are optimistic; EMBER2024 is chronological.
The "_work" folder is created by Guardian (unpacked zips); you can delete it any time.
