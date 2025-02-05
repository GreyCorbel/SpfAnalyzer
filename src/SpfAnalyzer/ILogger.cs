using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SpfAnalyzer
{
    /// <summary>
    /// Simple logger interface
    /// </summary>
    public interface ILogger
    {
        /// <summary>
        /// Log a message
        /// </summary>
        /// <param name="message">Message to log</param>
        void LogWarning(string message);
        void LogError(string message, Exception exception, int eventId, object? targetObject);
        void LogVerbose(string message);
    }
}
