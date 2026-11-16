using System.Text;

namespace Imw;

static class Program
{
    static int Main(string[] argv)
    {
        try
        {
            Console.OutputEncoding = new UTF8Encoding(false);
        }
        catch (IOException) { }
        return Cli.Run(argv);
    }
}
