POC implementation of "Efficient Full Domain Functional Bootstrapping from Recursive LUT Decomposition"

## How To Install
Use "go mod tidy"

## How To Run UnitTest
1. go to the "tfhe" folder (cd tfhe)
2. run go test command "go test"

## How To Run Benchmark
1. go to the "thfe" folder (cd tfhe)
2. run go benchmark command "go test -bench=. -benchtime=10x -timeout=0" (This runs 10 repetition of benchmark and output average elapsed time) 