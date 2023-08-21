class Error(BaseException):
    pass


class ParseError(Error):
    pass


class DumpError(Error):
    pass


class UpdateError(Error):
    pass


class AnnotateError(Error):
    pass


class EmailError(Error):
    pass


class UserMapError(Error):
    pass
