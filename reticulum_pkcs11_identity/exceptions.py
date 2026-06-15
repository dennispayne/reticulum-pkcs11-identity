# Reticulum PKCS#11 Identity - License
#
# Copyright (c) 2024 Contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


class PKCS11IdentityError(Exception):
    """Base exception for PKCS#11 identity errors."""
    pass


class PKCS11BackendError(PKCS11IdentityError):
    """Raised when the PKCS#11 backend encounters an error."""
    pass


class PKCS11SessionError(PKCS11IdentityError):
    """Raised when a PKCS#11 session cannot be established or is lost."""
    pass


class PKCS11LoginError(PKCS11IdentityError):
    """Raised when PKCS#11 login fails, e.g. incorrect PIN."""
    pass


class PKCS11KeyNotFoundError(PKCS11IdentityError):
    """Raised when the requested key is not found on the token."""
    pass


class PKCS11ConfigError(PKCS11IdentityError):
    """Raised when the PKCS#11 configuration is missing or invalid."""
    pass
