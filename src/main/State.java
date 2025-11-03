package main;

public sealed interface State {
    record START() implements State {
        public String name() {
            return this.getClass().getSimpleName();
        }
    }
    record WAITING() implements State {
        public String name() {
            return this.getClass().getSimpleName();
        }
    };
    record TALKING(String name) implements State {}

    public String name();
}
