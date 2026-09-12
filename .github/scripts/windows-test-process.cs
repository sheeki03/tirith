// CI-only process primitives. This file is never linked into the product.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TirithCi {
    public sealed class ProcessResult {
        public int ExitCode;
        public bool NativeJob, JobEmpty, LeaderReaped, OutputDrained, DescendantsLeaked;
        public string Error = "", CleanupError = "";
        public bool TimedOut;
        public bool OutputOverflow;
        public string Stdout = "";
        public string Stderr = "";
    }

    public sealed class StandardResult {
        public int ExitCode = -1;
        public bool TimedOut;
        public bool DescendantsLeaked;
        public bool JobEmpty;
        public string Sid = "";
        public string Profile = "";
        public bool Elevated;
        public bool AdministratorsPresent;
        public uint IntegrityRid;
        public uint ProcessId;
        public string Error = "";
    }

    public static class ProcessRunner {
        // Raw streams are drained concurrently with one shared byte budget. No
        // line reader may allocate an unbounded string before enforcing the cap.
        public static ProcessResult Run(string executable, string[] arguments, string cwd,
                IDictionary<string, string> environment, int timeoutSeconds, int maxBytes) {
            if (timeoutSeconds < 1 || maxBytes < 1) throw new ArgumentException("invalid process bounds");
            var start = new ProcessStartInfo(executable) {
                UseShellExecute = false, RedirectStandardOutput = true,
                RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = cwd
            };
            foreach (string argument in arguments) start.ArgumentList.Add(argument);
            if (environment != null) foreach (var pair in environment) {
                if (pair.Value == null) start.Environment.Remove(pair.Key);
                else start.Environment[pair.Key] = pair.Value;
            }
            if (OperatingSystem.IsWindows()) return StandardProcess.RunCurrent(start, timeoutSeconds, maxBytes);
            using (var process = new Process { StartInfo = start })
            using (var stdout = new MemoryStream())
            using (var stderr = new MemoryStream()) {
                if (!process.Start()) throw new IOException("process did not start");
                var result = new ProcessResult();
                long bytes = 0;
                int overflow = 0;
                Func<Stream, MemoryStream, Task> drain = async (source, destination) => {
                    byte[] buffer = new byte[8192];
                    for (;;) {
                        int read = await source.ReadAsync(buffer, 0, buffer.Length);
                        if (read == 0) break;
                        if (Interlocked.Add(ref bytes, read) > maxBytes) {
                            Interlocked.Exchange(ref overflow, 1);
                        } else if (Volatile.Read(ref overflow) == 0) {
                            destination.Write(buffer, 0, read);
                        }
                    }
                };
                Task outTask = drain(process.StandardOutput.BaseStream, stdout);
                Task errTask = drain(process.StandardError.BaseStream, stderr);
                Stopwatch clock = Stopwatch.StartNew();
                while (!process.WaitForExit(100)) {
                    if (Volatile.Read(ref overflow) != 0 || clock.Elapsed.TotalSeconds >= timeoutSeconds) {
                        result.TimedOut = clock.Elapsed.TotalSeconds >= timeoutSeconds;
                        process.Kill(true);
                        if (!process.WaitForExit(10000)) throw new IOException("process cleanup deadline exceeded");
                        break;
                    }
                }
                // A leaked descendant retaining an output pipe must not hang CI.
                if (!Task.WaitAll(new Task[] { outTask, errTask }, 10000))
                    throw new IOException("output pipe cleanup deadline exceeded");
                result.ExitCode = process.ExitCode;
                result.OutputOverflow = Volatile.Read(ref overflow) != 0;
                result.Stdout = Encoding.UTF8.GetString(stdout.ToArray());
                result.Stderr = Encoding.UTF8.GetString(stderr.ToArray());
                return result;
            }
        }
    }

    public static class StandardProcess {
        const uint CREATE_SUSPENDED = 0x4, CREATE_UNICODE_ENVIRONMENT = 0x400, CREATE_NO_WINDOW = 0x08000000;
        const uint TOKEN_QUERY = 0x8, KILL_ON_JOB_CLOSE = 0x2000;
        const uint WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 258;
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct StartupInfo {
            public int cb; public string reserved; public string desktop; public string title;
            public uint x, y, xSize, ySize, xCountChars, yCountChars, fillAttribute, flags;
            public ushort showWindow, reserved2Count; public IntPtr reserved2, stdin, stdout, stderr;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct ProcessInfo { public IntPtr process, thread; public uint pid, tid; }
        [StructLayout(LayoutKind.Sequential)]
        struct BasicLimits {
            public long perProcessUserTime, perJobUserTime; public uint flags;
            public UIntPtr minWorkingSet, maxWorkingSet; public uint activeProcessLimit;
            public UIntPtr affinity; public uint priorityClass, schedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct IoCounters { public ulong readOps, writeOps, otherOps, readBytes, writeBytes, otherBytes; }
        [StructLayout(LayoutKind.Sequential)]
        struct ExtendedLimits {
            public BasicLimits basic; public IoCounters io;
            public UIntPtr processMemory, jobMemory, peakProcessMemory, peakJobMemory;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct Accounting {
            public long userTime, kernelTime, periodUserTime, periodKernelTime;
            public uint pageFaults, totalProcesses, activeProcesses, terminatedProcesses;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct SidAndAttributes { public IntPtr sid; public uint attributes; }
        [StructLayout(LayoutKind.Sequential)]
        struct TokenGroupsFirst { public uint count; public SidAndAttributes first; }
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateProcessWithLogonW(string username, string domain, IntPtr password,
            uint logonFlags, string application, StringBuilder commandLine, uint creationFlags,
            IntPtr environment, string cwd, ref StartupInfo startup, out ProcessInfo process);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, uint size, out uint required);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetUserProfileDirectoryW(IntPtr token, StringBuilder path, ref uint size);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool DeleteProfileW(string sid, string profile, string computer);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetInformationJobObject(IntPtr job, int kind, ref ExtendedLimits info, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool QueryInformationJobObject(IntPtr job, int kind, out Accounting info, uint length, IntPtr returned);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool TerminateJobObject(IntPtr job, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool TerminateProcess(IntPtr process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);

        static void Require(bool success, string operation) {
            if (!success) throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
        }
        static IntPtr TokenData(IntPtr token, int kind) {
            uint length;
            GetTokenInformation(token, kind, IntPtr.Zero, 0, out length);
            if (length == 0 || length > 1024 * 1024) throw new IOException("invalid token information length");
            IntPtr data = Marshal.AllocHGlobal((int)length);
            try { Require(GetTokenInformation(token, kind, data, length, out length), "GetTokenInformation"); return data; }
            catch { Marshal.FreeHGlobal(data); throw; }
        }
        static void Attest(IntPtr process, string expectedSid, StandardResult result) {
            IntPtr token;
            Require(OpenProcessToken(process, TOKEN_QUERY, out token), "OpenProcessToken");
            try {
                IntPtr user = TokenData(token, 1);
                try { result.Sid = new SecurityIdentifier(Marshal.ReadIntPtr(user)).Value; }
                finally { Marshal.FreeHGlobal(user); }
                IntPtr elevation = TokenData(token, 20);
                try { result.Elevated = Marshal.ReadInt32(elevation) != 0; }
                finally { Marshal.FreeHGlobal(elevation); }
                IntPtr groups = TokenData(token, 2);
                try {
                    int count = Marshal.ReadInt32(groups);
                    if (count < 0 || count > 4096) throw new IOException("invalid token group count");
                    int offset = Marshal.OffsetOf<TokenGroupsFirst>("first").ToInt32();
                    int size = Marshal.SizeOf<SidAndAttributes>();
                    for (int i = 0; i < count; ++i) {
                        var group = Marshal.PtrToStructure<SidAndAttributes>(IntPtr.Add(groups, offset + i * size));
                        if (new SecurityIdentifier(group.sid).Value == "S-1-5-32-544") result.AdministratorsPresent = true;
                    }
                } finally { Marshal.FreeHGlobal(groups); }
                IntPtr integrity = TokenData(token, 25);
                try {
                    string value = new SecurityIdentifier(Marshal.ReadIntPtr(integrity)).Value;
                    string[] parts = value.Split('-');
                    result.IntegrityRid = uint.Parse(parts[parts.Length - 1]);
                } finally { Marshal.FreeHGlobal(integrity); }
                uint length = 32768;
                var profile = new StringBuilder((int)length);
                Require(GetUserProfileDirectoryW(token, profile, ref length), "GetUserProfileDirectoryW");
                result.Profile = profile.ToString();
                if (result.Sid != expectedSid || result.Elevated || result.AdministratorsPresent || result.IntegrityRid > 8192)
                    throw new IOException("suspended worker token is not the expected standard account");
            } finally { CloseHandle(token); }
        }
        static bool Empty(IntPtr job) {
            Accounting info;
            Require(QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf<Accounting>(), IntPtr.Zero), "QueryInformationJobObject");
            return info.activeProcesses == 0;
        }
        static bool WaitEmpty(IntPtr job, int milliseconds) {
            Stopwatch clock = Stopwatch.StartNew();
            do { if (Empty(job)) return true; Thread.Sleep(50); } while (clock.ElapsedMilliseconds < milliseconds);
            return Empty(job);
        }
        static string Quote(string value) {
            // Every argument here is a fixed switch or canonical path, never a
            // shell expression. Embedded quotes/control characters are refused.
            if (value.IndexOf('"') >= 0 || value.IndexOf('\n') >= 0 || value.IndexOf('\r') >= 0 || value.EndsWith("\\"))
                throw new ArgumentException("invalid native command argument");
            return "\"" + value + "\"";
        }
        public static StandardResult Run(string username, SecureString password, string expectedSid,
                string executable, string worker, string manifest, string cwd, int timeoutSeconds) {
            if (!OperatingSystem.IsWindows() || timeoutSeconds < 1 || timeoutSeconds > 900)
                throw new ArgumentException("invalid standard-account process request");
            var result = new StandardResult();
            var info = new ProcessInfo();
            IntPtr job = IntPtr.Zero, secret = IntPtr.Zero;
            bool assigned = false;
            try {
                job = CreateJobObjectW(IntPtr.Zero, null);
                Require(job != IntPtr.Zero, "CreateJobObjectW");
                var limits = new ExtendedLimits(); limits.basic.flags = KILL_ON_JOB_CLOSE;
                Require(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()), "SetInformationJobObject");
                string command = Quote(executable) + " -NoLogo -NoProfile -NonInteractive -File " + Quote(worker) + " -Manifest " + Quote(manifest);
                if (command.Length >= 1024) throw new IOException("native logon command exceeds bound");
                var startup = new StartupInfo(); startup.cb = Marshal.SizeOf<StartupInfo>();
                secret = Marshal.SecureStringToGlobalAllocUnicode(password);
                // LOGON_WITH_PROFILE and null environment create a real profile
                // environment. No CI secrets or caller token are inherited.
                Require(CreateProcessWithLogonW(username, ".", secret, 1, executable, new StringBuilder(command),
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                    IntPtr.Zero, cwd, ref startup, out info), "CreateProcessWithLogonW");
                Marshal.ZeroFreeGlobalAllocUnicode(secret); secret = IntPtr.Zero;
                result.ProcessId = info.pid;
                Attest(info.process, expectedSid, result);
                Require(AssignProcessToJobObject(job, info.process), "AssignProcessToJobObject");
                assigned = true;
                Require(ResumeThread(info.thread) != 0xffffffff, "ResumeThread");
                uint wait = WaitForSingleObject(info.process, checked((uint)timeoutSeconds * 1000));
                if (wait == WAIT_TIMEOUT) result.TimedOut = true;
                else Require(wait == WAIT_OBJECT_0, "WaitForSingleObject");
                if (!result.TimedOut) {
                    uint code; Require(GetExitCodeProcess(info.process, out code), "GetExitCodeProcess");
                    result.ExitCode = unchecked((int)code);
                    result.DescendantsLeaked = !WaitEmpty(job, 10000);
                }
            } catch (Exception error) { result.Error = error.GetType().Name + ": " + error.Message; }
            finally {
                if (secret != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(secret);
                try {
                    if (assigned) {
                        Require(TerminateJobObject(job, 1), "TerminateJobObject");
                        result.JobEmpty = WaitEmpty(job, 10000);
                    } else if (info.process != IntPtr.Zero) {
                        Require(TerminateProcess(info.process, 1), "TerminateProcess suspended worker");
                        result.JobEmpty = WaitForSingleObject(info.process, 10000) == WAIT_OBJECT_0;
                    } else result.JobEmpty = true;
                } catch (Exception error) { result.Error += "; cleanup: " + error.Message; }
                if (info.thread != IntPtr.Zero) CloseHandle(info.thread);
                if (info.process != IntPtr.Zero) CloseHandle(info.process);
                if (job != IntPtr.Zero) CloseHandle(job);
            }
            return result;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct SecurityAttributes { public int length; public IntPtr security; [MarshalAs(UnmanagedType.Bool)] public bool inherit; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct StartupInfoEx { public StartupInfo startup; public IntPtr attributes; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes,
            IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string cwd,
            ref StartupInfoEx startup, out ProcessInfo process);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr bytes);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute,
            IntPtr value, IntPtr bytes, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")]
        static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string path, uint access, uint sharing,
            ref SecurityAttributes security, uint creation, uint attributes, IntPtr template);

        // The servers use overlapped I/O, so a drainage deadline can cancel the
        // readers instead of leaving blocked synchronous ReadFile workers behind.
        sealed class OutputPipe : IDisposable {
            public readonly NamedPipeServerStream Reader;
            public readonly NamedPipeClientStream Writer;
            public OutputPipe() {
                string name = "tirith-ci-" + Guid.NewGuid().ToString("N");
                Reader = new NamedPipeServerStream(name, PipeDirection.In, 1, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                try {
                    Task connected = Reader.WaitForConnectionAsync();
                    Writer = new NamedPipeClientStream(".", name, PipeDirection.Out, PipeOptions.None,
                        TokenImpersonationLevel.Anonymous, HandleInheritability.Inheritable);
                    Writer.Connect(5000);
                    if (!connected.Wait(5000)) throw new IOException("private output pipe connection deadline exceeded");
                } catch { if (Writer != null) Writer.Dispose(); Reader.Dispose(); throw; }
            }
            public void Dispose() { Writer.Dispose(); Reader.Dispose(); }
        }

        sealed class OutputCapture : IDisposable {
            readonly object gate = new object();
            readonly MemoryStream stdout = new MemoryStream(), stderr = new MemoryStream();
            readonly CancellationTokenSource cancellation = new CancellationTokenSource();
            readonly int limit;
            long bytes;
            public int Overflow;
            public OutputCapture(int maximum) { limit = maximum; }
            public async Task<bool> Drain(Stream source, bool isError) {
                byte[] buffer = new byte[8192];
                try {
                    for (;;) {
                        int read = await source.ReadAsync(buffer, 0, buffer.Length, cancellation.Token);
                        if (read == 0) return true;
                        lock (gate) {
                            bytes += read;
                            if (bytes > limit) Interlocked.Exchange(ref Overflow, 1);
                            else if (Volatile.Read(ref Overflow) == 0)
                                (isError ? stderr : stdout).Write(buffer, 0, read);
                        }
                    }
                } catch (Exception) {
                    // A cancelled, closed or failed read is never certified EOF.
                    return false;
                }
            }
            public void Cancel() { cancellation.Cancel(); }
            public void CopyTo(ProcessResult result) {
                lock (gate) {
                    result.Stdout = Encoding.UTF8.GetString(stdout.ToArray());
                    result.Stderr = Encoding.UTF8.GetString(stderr.ToArray());
                    result.OutputOverflow = Volatile.Read(ref Overflow) != 0;
                }
            }
            public void Dispose() { cancellation.Dispose(); stdout.Dispose(); stderr.Dispose(); }
        }

        static string NativeArgument(string value) {
            if (value == null || value.IndexOf('\0') >= 0) throw new ArgumentException("invalid native argument");
            var quoted = new StringBuilder("\"");
            int slashes = 0;
            foreach (char character in value) {
                if (character == '\\') { slashes++; continue; }
                if (character == '"') quoted.Append('\\', slashes * 2 + 1).Append('"');
                else quoted.Append('\\', slashes).Append(character);
                slashes = 0;
            }
            return quoted.Append('\\', slashes * 2).Append('"').ToString();
        }
        static string NativeEnvironment(ProcessStartInfo start) {
            var sorted = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var pair in start.Environment) sorted[pair.Key] = pair.Value;
            var block = new StringBuilder();
            foreach (var pair in sorted) {
                if (pair.Value == null) continue;
                if (pair.Key.Length == 0 || pair.Key.IndexOf('\0') >= 0 || pair.Value.IndexOf('\0') >= 0 ||
                    pair.Key.IndexOf('=', 1) >= 0) throw new ArgumentException("invalid environment entry");
                block.Append(pair.Key).Append('=').Append(pair.Value).Append('\0');
                if (block.Length > 524288) throw new IOException("process environment exceeds bound");
            }
            // Include both terminators even for an otherwise empty environment.
            if (block.Length == 0) block.Append('\0');
            return block.Append('\0').ToString();
        }

        // Ordinary CI build/test children need the same lifetime guarantee as
        // the standard-account worker. Assign the suspended process before its
        // first instruction; assigning a running Process would race early forks.
        internal static ProcessResult RunCurrent(ProcessStartInfo start, int timeoutSeconds, int maxBytes) {
            var result = new ProcessResult { ExitCode = -1, NativeJob = true };
            var info = new ProcessInfo();
            IntPtr job = IntPtr.Zero, attributes = IntPtr.Zero, handles = IntPtr.Zero, environment = IntPtr.Zero;
            bool initialized = false, assigned = false;
            OutputPipe output = null, error = null;
            SafeFileHandle input = null;
            var capture = new OutputCapture(maxBytes);
            Task<bool> outTask = null, errTask = null;
            try {
                if (!Path.IsPathFullyQualified(start.FileName) || !Path.IsPathFullyQualified(start.WorkingDirectory))
                    throw new ArgumentException("native CI paths must be absolute");
                var command = new StringBuilder(NativeArgument(start.FileName));
                foreach (string argument in start.ArgumentList) command.Append(' ').Append(NativeArgument(argument));
                if (command.Length >= 32767) throw new IOException("native command exceeds bound");
                environment = Marshal.StringToHGlobalUni(NativeEnvironment(start));
                output = new OutputPipe(); error = new OutputPipe();
                var security = new SecurityAttributes { length = Marshal.SizeOf<SecurityAttributes>(), inherit = true };
                input = CreateFileW("NUL", 0x80000000, 3, ref security, 3, 0, IntPtr.Zero);
                Require(!input.IsInvalid, "CreateFileW NUL");
                job = CreateJobObjectW(IntPtr.Zero, null);
                Require(job != IntPtr.Zero, "CreateJobObjectW current-account child");
                var limits = new ExtendedLimits(); limits.basic.flags = KILL_ON_JOB_CLOSE;
                Require(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()), "SetInformationJobObject current-account child");
                IntPtr bytes = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
                if (bytes.ToInt64() <= 0 || bytes.ToInt64() > 65536) throw new IOException("invalid native attribute-list size");
                attributes = Marshal.AllocHGlobal(bytes);
                Require(InitializeProcThreadAttributeList(attributes, 1, 0, ref bytes), "InitializeProcThreadAttributeList");
                initialized = true;
                handles = Marshal.AllocHGlobal(3 * IntPtr.Size);
                Marshal.WriteIntPtr(handles, 0, input.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, IntPtr.Size, output.Writer.SafePipeHandle.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, 2 * IntPtr.Size, error.Writer.SafePipeHandle.DangerousGetHandle());
                Require(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handles,
                    new IntPtr(3 * IntPtr.Size), IntPtr.Zero, IntPtr.Zero), "UpdateProcThreadAttribute handle list");
                var startup = new StartupInfoEx();
                startup.startup.cb = Marshal.SizeOf<StartupInfoEx>();
                startup.startup.flags = 0x100; // STARTF_USESTDHANDLES
                startup.startup.stdin = input.DangerousGetHandle();
                startup.startup.stdout = output.Writer.SafePipeHandle.DangerousGetHandle();
                startup.startup.stderr = error.Writer.SafePipeHandle.DangerousGetHandle();
                startup.attributes = attributes;
                Require(CreateProcessW(start.FileName, command, IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | 0x80000,
                    environment, start.WorkingDirectory, ref startup, out info), "CreateProcessW suspended CI child");
                Require(AssignProcessToJobObject(job, info.process), "AssignProcessToJobObject before resume");
                assigned = true;
                Require(ResumeThread(info.thread) != 0xffffffff, "ResumeThread CI child");
                // Only the explicitly inherited child handles may keep these
                // channels open. The controller drops its own writer copies.
                output.Writer.Dispose(); error.Writer.Dispose(); input.Dispose();
                outTask = capture.Drain(output.Reader, false);
                errTask = capture.Drain(error.Reader, true);
                Stopwatch clock = Stopwatch.StartNew();
                for (;;) {
                    uint wait = WaitForSingleObject(info.process, 100);
                    if (wait == WAIT_OBJECT_0) {
                        result.LeaderReaped = true;
                        uint code; Require(GetExitCodeProcess(info.process, out code), "GetExitCodeProcess CI child");
                        result.ExitCode = unchecked((int)code);
                        if (Volatile.Read(ref capture.Overflow) == 0) result.DescendantsLeaked = !WaitEmpty(job, 10000);
                        break;
                    }
                    Require(wait == WAIT_TIMEOUT, "WaitForSingleObject CI child");
                    if (Volatile.Read(ref capture.Overflow) != 0 || clock.Elapsed.TotalSeconds >= timeoutSeconds) {
                        result.TimedOut = clock.Elapsed.TotalSeconds >= timeoutSeconds;
                        break;
                    }
                }
            } catch (Exception exception) { result.Error = exception.GetType().Name + ": " + exception.Message; }
            finally {
                try {
                    if (assigned) {
                        Require(TerminateJobObject(job, 1), "TerminateJobObject CI child tree");
                        result.JobEmpty = WaitEmpty(job, 10000);
                    } else if (info.process != IntPtr.Zero) {
                        Require(TerminateProcess(info.process, 1), "TerminateProcess suspended CI child");
                    }
                    if (info.process != IntPtr.Zero) result.LeaderReaped = WaitForSingleObject(info.process, 10000) == WAIT_OBJECT_0;
                    if (!result.LeaderReaped || !result.JobEmpty) result.CleanupError = "native process tree cleanup was not confirmed";
                } catch (Exception exception) { result.CleanupError = exception.GetType().Name + ": " + exception.Message; }
                if (output != null) output.Writer.Dispose();
                if (error != null) error.Writer.Dispose();
                if (input != null) input.Dispose();
                try {
                    if (outTask != null && errTask != null && Task.WaitAll(new Task[] { outTask, errTask }, 10000))
                        result.OutputDrained = outTask.Result && errTask.Result;
                    if (!result.OutputDrained) result.CleanupError += "; bounded output EOF was not confirmed";
                } catch (Exception exception) { result.CleanupError += "; " + exception.GetType().Name + ": output drainage failed"; }
                capture.Cancel();
                if (output != null) output.Dispose();
                if (error != null) error.Dispose();
                // Overlapped pipe cancellation is bounded independently of child
                // lifetime; never return success for a reader that did not stop.
                bool stopped = outTask == null || errTask == null || Task.WaitAll(new Task[] { outTask, errTask }, 2000);
                if (!stopped) result.CleanupError += "; output reader cancellation deadline exceeded";
                capture.CopyTo(result);
                if (stopped) capture.Dispose();
                if (info.thread != IntPtr.Zero) CloseHandle(info.thread);
                if (info.process != IntPtr.Zero) CloseHandle(info.process);
                if (job != IntPtr.Zero) CloseHandle(job);
                if (initialized) DeleteProcThreadAttributeList(attributes);
                if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
                if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
            }
            if (result.Error.Length != 0 || result.CleanupError.Length != 0 || result.DescendantsLeaked)
                result.ExitCode = -1;
            return result;
        }

        public static void RemoveProfile(string sid, string profile) {
            Require(DeleteProfileW(sid, profile, null), "DeleteProfileW");
        }
    }
}
