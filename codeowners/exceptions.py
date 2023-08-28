from subprocess import CalledProcessError


class Error(Exception):
    pass


class CommandError(Error):
    def __init__(self, e: CalledProcessError) -> None:
        if isinstance(e.stderr, bytes):
            stderr = e.stderr.decode()
        elif isinstance(e.stderr, str):
            stderr = e.stderr
        else:
            message = "Stderr type must be bytes or str"
            raise TypeError(message)

        message = f"Subprocess failed [{e.returncode}]: {stderr!r}"
        super().__init__(message)


class FileAccessError(Error):
    def __init__(self, e: OSError) -> None:
        message = f"Unable to access file: {e.strerror}"
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


class MalformedMergeConflictError(CodeownersParseError):
    def __init__(self, line_number: int) -> None:
        message = "Merge conflict does not have proper ending"
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
        message = "Git annotate line does not match email regex."
        super().__init__(message)
