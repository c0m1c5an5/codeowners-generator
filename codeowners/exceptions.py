class Error(Exception):
    pass


class CommandError(Error):
    def __init__(self, err: str) -> None:
        message = err
        super().__init__(message)


class CodeownersParseError(Error):
    def __init__(self, line_number: int, message: str) -> None:
        message = f"Parsing error at line '{line_number}': {message}"
        super().__init__(message)


class SectionsNotSupportedError(CodeownersParseError):
    def __init__(self, line_number: int) -> None:
        message = "Sections are not supported"
        super().__init__(line_number, message)


class MissingOwnersError(CodeownersParseError):
    def __init__(self, line_number: int) -> None:
        message = "At least one owner has to be provided"
        super().__init__(line_number, message)


class UserMapParseError(Error):
    def __init__(self, message: str) -> None:
        message = f"Json parsing failed: {message}"
        super().__init__(message)


class GitEmailEmptyError(Error):
    def __init__(self) -> None:
        message = "Email string is empty"
        super().__init__(message)


class GitAnnotateError(Error):
    def __init__(self) -> None:
        message = "Git annotate line does not match email regex"
        super().__init__(message)
