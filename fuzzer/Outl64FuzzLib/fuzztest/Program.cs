using System;
using Outl64FuzzLib;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices.ComTypes;
using System.Diagnostics;

namespace fuzztest
{
    class Program
    {
        [DllImport("ole32.Dll")]
        static public extern uint CoCreateInstance(ref Guid clsid, [MarshalAs(UnmanagedType.IUnknown)] object inner, uint context, ref Guid uuid, [MarshalAs(UnmanagedType.IUnknown)] out object rReturnedComObject);
        static string DEFAULT_TNEF = "..\\..\\..\\mails\\exp.tnef";
        static string DEFAULT_CERT = "..\\..\\..\\mails\\cert.p7s";
        enum LogLevel :int
        {
            DEBUG=0,
            INFO = 1,
            WARNING = 2,
            ERROR = 3,
            FATAL = 4
        };

        struct Params
        {
            public bool outproc;
            public bool verbose;
            public bool help;
            public bool wait;
            public string command;
            public string[] files;
            public MapiFuzz mapi;
        };

        static Dictionary<string, Func<Params, bool>> commands = new Dictionary<string, Func<Params, bool>>
        {
            { "version", Version },
            { "fname", Filename },
            { "stream", Stream },
            { "buf", Buf },
            { "nomock", NoMock },
            { "message", Message },
            { "cert", Cert },
            { "crash", Crash },
            { "test", Test },
        };

        static void Usage()
        {
            Console.WriteLine(string.Format(
@"Usage: fuzztest [options] [command] [files]

options:
        -o      - outproc com initialization.
        -w      - wait for keypress after execution.
        -v      - verbose output.
        -h      - help.

commands:"));      
            foreach(string cmd in commands.Keys)
            {
                Func<Params, bool> func = commands[cmd];
                DescriptionAttribute a = (DescriptionAttribute)func.GetMethodInfo().GetCustomAttribute(typeof(DescriptionAttribute));
                string descr = null == "a" ? "description un" : a.Description;
                Console.WriteLine(string.Format("\t{0}\t - {1}",cmd, descr));
            }
            Console.WriteLine(string.Format("\nfiles:\n\tTnef files array.\n\tDefault file: {0}", defaultFile("")));
        }

        static string defaultFile(string cmd)
        {
            string mpath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string tnef=Path.Combine(mpath, cmd=="cert" ? DEFAULT_CERT : DEFAULT_TNEF);
            return Path.GetFullPath(tnef);
        }


        static Params GetParams(string[] args)
        {
            Params p = new Params();
            List<string> files = new List<string>();
            foreach (string s in args)
            {
                if (s.StartsWith("-")){
                    foreach(char c in s)
                    {
                        if (c == 'o') p.outproc = true;
                        if (c == 'v') p.verbose = true;
                        if (c == 'w') p.wait = true;
                        if (c == 'h') p.help = true;
                    }
                    continue;
                }
                if (commands.ContainsKey(s) && null==p.command)
                {
                    p.command = s;
                    continue;
                }
                if (File.Exists(s))
                {
                    files.Add(s);
                    continue;
                }
                throw new Exception("File not found: " + s);
            }
            if (p.command == null)
            {
                p.command = files.Count == 0 ? "version" : "fname";
            }
            if (files.Count == 0)
            {
                files.Add(defaultFile(p.command));
            }
            p.files = files.ToArray();
            return p;
        }


        static bool CreateMapiFuzz(ref Params p)
        {
            if (!p.outproc)
            {
                p.mapi = new MapiFuzz();
            }
            else unsafe
            {
                Guid clsid = new Guid("2FD04774-5788-4BBA-B925-71AFBC0A38C7");
                Guid iunk = new Guid("00000000-0000-0000-C000-000000000046");
                object obj;
                uint LOCAL_SERVER = 4;
                uint err = CoCreateInstance(ref clsid, null, LOCAL_SERVER, ref iunk, out obj);
                if (err != 0)
                {
                    throw new Exception(string.Format("Error creating instance: 0x{0:X}", err));
                }
                p.mapi = obj as MapiFuzz;
            }
            p.mapi.log+= Mapi_log;
            if (p.verbose)
            {
                p.mapi.config(0);
            }
            return true;
        }

        private static void Mapi_log(int level, string message)
        {
            Console.WriteLine(string.Format("FUZZLIB {0}: {1}",((LogLevel)level).ToString(),message));
        }

        [Description("prints version. Default command if no files specified.")]
        private static bool Version(Params p)
        {
            Console.WriteLine("Version: "+p.mapi.version());
            return true;
        }

        [Description("parse tnef by filename. Default command if files specified.")]
        private static bool Filename(Params p)
        {
            if (p.files.Length == 1)
            {
                p.mapi.parseTnef(p.files[0], 1);
            }
            else
            {
                p.mapi.parseTnef(p.files, 1);
            }
            return true;
        }

        [Description("parse tnef by stream.")]
        private static bool Stream(Params p)
        {
            List<IStream> lst = new List<IStream>();
            foreach (string s in p.files)
            {
                lst.Add(new CComFileStream(s));
            }
            if (lst.Count == 1)
            {
                p.mapi.parseTnef(lst[0], 1);
            }
            else
            {
                p.mapi.parseTnef(lst, 1);
            }
            return true;
        }

        [Description("parse tnef in bytebuffer.")]
        private static bool Buf(Params p)
        {
            foreach(string f in p.files)
            {
                FileStream fs = new FileStream(f, FileMode.Open);
                byte[] arr = new byte[fs.Length];
                fs.Read(arr, 0, (int)fs.Length);
                fs.Close();
                p.mapi.parseTnef(arr, 1);
            }
            return true;
        }

        [Description("parse tnef to real message.")]
        private static bool NoMock(Params p)
        {
            if (p.files.Length == 1)
            {
                p.mapi.parseTnef(p.files[0], 0);
            }
            else
            {
                p.mapi.parseTnef(p.files, 0);
            }
            return true;
        }

        [Description("create IMessage with props from file.")]
        private static bool Message(Params p)
        {
            if (p.files.Length == 1)
            {
                p.mapi.createMessage(p.files[0]);
            }
            else
            {
                p.mapi.createMessage(p.files);
            }
            return true;
        }

        [Description("Parse p7s cert container.")]
        private static bool Cert(Params p)
        {
            if (p.files.Length == 1)
            {
                p.mapi.parseCert(p.files[0]);
            }
            else
            {
                p.mapi.parseCert(p.files);
            }
            return true;
        }

        [Description("Raise exception in library.")]
        private static bool Crash(Params p)
        {
            p.mapi.crash(0);
            return true;
        }


        [Description("Run some tests.")]
        private static bool Test(Params p)
        {
            FileStream fs = new FileStream(p.files[0], FileMode.Open);
            byte[] arr = new byte[fs.Length];
            fs.Read(arr, 0, (int)fs.Length);
            fs.Close();
            int i = 0;
            while (i < 0x80FF)
            {
                i += 1;
                if (i == 0x7FFE)
                {
                    p.mapi.config(0);
                }
                if (i % 1000 == 0)
                {
                    Console.WriteLine(String.Format("Step {0}", i));
                }
                p.mapi.parseTnef(arr, 0);
            }
            return true;
        }


        static void Main(string[] args)
        {
            Params p;
            p.wait = false;
            try
            {
                p = GetParams(args);
                if (p.verbose)
                {
                    Console.WriteLine(String.Format("fuzztest {0}bit\ncommand: {1}\nfiles: {2}\n", IntPtr.Size == 4 ? 32 : 64, 
                        p.command, string.Join(" ",p.files)));
                }
                if (p.help)
                {
                    Usage();
                }
                if (!p.help && CreateMapiFuzz(ref p))
                {
                    commands[p.command](p);
                }
            }catch(Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            if (p.wait)
            {
                Console.ReadKey(true);
            }
        }

    }
}
