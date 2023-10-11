class InvalidParametersException extends Exception{
    public InvalidParametersException(String message) {
        super(message);
    }
}

class WrongPassphraseException extends Exception{
    public WrongPassphraseException(String message) {
        super(message);
    }
}

class FileException extends Exception{
    public FileException(String message) {
        super(message);
    }
}

class SignException extends Exception{
    public SignException(String message) {
        super(message);
    }
}
