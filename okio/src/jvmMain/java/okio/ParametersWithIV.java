package okio;

public class ParametersWithIV
{
    private byte[]              iv;
    private KeyParameter    parameters;

    public ParametersWithIV(
        KeyParameter    parameters,
        byte[]              iv)
    {
        this(parameters, iv, 0, iv.length);
    }

    public ParametersWithIV(
        KeyParameter    parameters,
        byte[]              iv,
        int                 ivOff,
        int                 ivLen)
    {
        this.iv = new byte[ivLen];
        this.parameters = parameters;

        System.arraycopy(iv, ivOff, this.iv, 0, ivLen);
    }

    public byte[] getIV()
    {
        return iv;
    }

    public KeyParameter getParameters()
    {
        return parameters;
    }
}
