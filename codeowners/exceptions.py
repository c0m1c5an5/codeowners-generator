class Error(Exception):
    pass


class GitEmailEmptyError(Error):
    def __init__(self) -> None:
        message = "Git email string is empty"
        super().__init__(message)


class GitAnnotateError(Error):
    line: str

    def __init__(self, line: str) -> None:
        message = "Unexpected git blame output"
        self.line = line

        super().__init__(":".join((message, self.line)))


class GitAuthorMissingError(Error):
    sha: str

    def __init__(self, sha: str) -> None:
        message = "Blamed commit was never given an author"
        self.sha = sha

        super().__init__(":".join((message, self.sha)))
