# LiteRT-LM 0.18.1 reports native failures by looking up this exception by name.
-keep class com.google.ai.edge.litertlm.LiteRtLmJniException {
    public <init>(java.lang.String);
}
