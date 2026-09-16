mkdir bin/howlong
gcc ./workflow/how-long/src/main.c -o bin/howlong/bin/howlong

echo "\n\n# howlong\nexport PATH=$(realpath ./bin/howlong/bin):\$PATH\n# howlong end\n" >> ~/.zshrc
source ~/.zshrc

echo Successfully added 'howlong' to PATH
