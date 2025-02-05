using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using SpfAnalyzer;

namespace AutomationHelper
{
    public class Logger:ILogger
    {
        private readonly PSCmdlet _cmdlet;
        public Logger(PSCmdlet cmdlet)
        {
            _cmdlet = cmdlet;
        }
        public void LogWarning(string message)
        {
            _cmdlet.WriteWarning(message);
        }
        public void LogError(string message, Exception? exception, int eventId, Object? targetObject )
        {
            ErrorCategory category = ErrorCategory.NotSpecified;
            if(Enum.IsDefined(typeof(ErrorCategory), eventId))
            {
                category = (ErrorCategory)eventId;
            }
            var err = new ErrorRecord(exception ?? new Exception(message), message, category, targetObject);
            _cmdlet.WriteError(err);
        }
        public void LogVerbose(string message)
        {
            _cmdlet.WriteVerbose(message);
        }
    }
}
