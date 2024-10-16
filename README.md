# Demo ORDL Contract

## Requirements
Python 3.12+

## Development
1. If you don't have `Poetry` installed run:
    ```bash
    pip install poetry
    ```

2. Install dependencies:
    ```bash
    poetry config virtualenvs.in-project true
    poetry install --no-root --with dev,test
    ```

3. Launch the project:
    ```bash
    poetry run python -m app.usecases
    ```

## License
MIT

## Collaboration guidelines
HIRO uses and requires from its partners [GitFlow with Forks](https://hirodevops.notion.site/GitFlow-with-Forks-3b737784e4fc40eaa007f04aed49bb2e?pvs=4)
