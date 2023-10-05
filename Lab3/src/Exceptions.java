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
