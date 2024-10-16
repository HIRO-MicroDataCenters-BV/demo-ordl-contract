# Demo ORDL Contract

* Use case 1: Sign contract and use data
  ![Use case 1](docs/usecase1.jpg)

## Requirements
Python 3.12+

## Installation
```bash
pip install pre-commit
pre-commit install
```

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

3. Launch the usecase:
  **Use case 1: Sign contract and use data**
    ```bash
    poetry run python -m app.usecases
    ```

## License
MIT

## Collaboration guidelines
HIRO uses and requires from its partners [GitFlow with Forks](https://hirodevops.notion.site/GitFlow-with-Forks-3b737784e4fc40eaa007f04aed49bb2e?pvs=4)
