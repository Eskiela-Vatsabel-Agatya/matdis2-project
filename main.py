# menjalankan program melalui antarmuka baris perintah.
import sys

from cli import run


# meneruskan argumen ke antarmuka program.
def main() -> None:
    run(sys.argv[1:])


if __name__ == "__main__":
    main()
