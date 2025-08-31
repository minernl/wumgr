using System;
using System.Collections.Generic;
using System.Windows.Threading;


/// <summary>
///     Singleton class for logging application messages.
/// </summary>
internal class AppLog
{
    private static AppLog mInstance = null;
    private readonly Dispatcher mDispatcher;
    private readonly List<string> mLogList = new List<string>();

    /// <summary>
    ///     Initializes a new instance of the <see cref="AppLog" /> class.
    /// </summary>
    public AppLog()
    {
        mInstance = this;
        mDispatcher = Dispatcher.CurrentDispatcher;
        Logger += LineLogger;
    }

    /// <summary>
    ///     Logs a formatted message.
    /// </summary>
    /// <param name="str">The message format string.</param>
    /// <param name="args">The arguments to format the message.</param>
    public static void Line(string str, params object[] args)
    {
        Line(string.Format(str, args));
    }

    /// <summary>
    ///     Logs a message.
    /// </summary>
    /// <param name="line">The message to log.</param>
    public static void Line(string line)
    {
        if (mInstance != null)
            mInstance.LogLine(line);
    }

    /// <summary>
    ///     Logs a message and manages the log list.
    /// </summary>
    /// <param name="line">The message to log.</param>
    private void LogLine(string line)
    {
        mDispatcher.BeginInvoke(new Action(() => {
            mLogList.Add(line);
            while (mLogList.Count > 100)
                mLogList.RemoveAt(0);

            Logger?.Invoke(this, new LogEventArgs(line));
        }));
    }

    /// <summary>
    ///     Gets the log list.
    /// </summary>
    /// <returns>A list of log messages.</returns>
    public static List<string> GetLog() 
    { 
        return mInstance.mLogList; 
    }

    /// <summary>
    ///     Event triggered when a new log message is added.
    /// </summary>
    public static event EventHandler<LogEventArgs> Logger;

    /// <summary>
    ///     Logs the message to the console.
    /// </summary>
    /// <param name="sender">The event sender.</param>
    /// <param name="args">The log event arguments.</param>
    private static void LineLogger(object sender, LogEventArgs args)
    {
        Console.WriteLine("LOG: " + args.line);
    }

    /// <summary>
    ///     Gets the singleton instance of the <see cref="AppLog" /> class.
    /// </summary>
    /// <returns>The singleton instance.</returns>
    public static AppLog GetInstance() 
    { 
        return mInstance; 
    }

    /// <summary>
    ///     Event arguments for log events.
    /// </summary>
    public class LogEventArgs : EventArgs
    {
        /// <summary>
        ///     Initializes a new instance of the <see cref="LogEventArgs" /> class.
        /// </summary>
        /// <param name="line">The log message.</param>
        public LogEventArgs(string _line) 
        { 
            this.line = _line; 
        }
        
        /// <summary>
        ///     Gets or sets the log message.
        /// </summary>
        public string line { get; set; }
    }

    
}
