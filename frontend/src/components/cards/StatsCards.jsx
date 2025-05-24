import { useData } from "../../context/DataContext";

const StatCard = ({ title, value, icon, colorClass = "text-primary-500" }) => (
  <div className="dashboard-card flex flex-col p-4">
    <div className="flex justify-between items-start">
      <div>
        <p className="text-dark-400 text-xs mb-1">{title}</p>
        <p className={`text-xl font-bold ${colorClass}`}>{value}</p>
      </div>
      <div className={`p-2 rounded ${colorClass} bg-opacity-10`}>
        {icon}
      </div>
    </div>
  </div>
);

const AlertIcon = ({ className = "h-5 w-5" }) => (
  <svg xmlns="http://www.w3.org/2000/svg" className={className} viewBox="0 0 20 20" fill="currentColor">
    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
  </svg>
);

const ErrorIcon = ({ className = "h-5 w-5" }) => (
  <svg xmlns="http://www.w3.org/2000/svg" className={className} viewBox="0 0 20 20" fill="currentColor">
    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
  </svg>
);

const WarningIcon = ({ className = "h-5 w-5" }) => (
  <svg xmlns="http://www.w3.org/2000/svg" className={className} viewBox="0 0 20 20" fill="currentColor">
    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
  </svg>
);

const AttackIcon = ({ className = "h-5 w-5" }) => (
  <svg xmlns="http://www.w3.org/2000/svg" className={className} viewBox="0 0 20 20" fill="currentColor">
    <path fillRule="evenodd" d="M3 6a3 3 0 013-3h10a1 1 0 01.8 1.6L14.25 8l2.55 3.4A1 1 0 0116 13H6a1 1 0 00-1 1v3a1 1 0 11-2 0V6z" clipRule="evenodd" />
  </svg>
);

const UniqueIcon = ({ className = "h-5 w-5" }) => (
  <svg xmlns="http://www.w3.org/2000/svg" className={className} viewBox="0 0 20 20" fill="currentColor">
    <path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z" />
    <path fillRule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z" clipRule="evenodd" />
  </svg>
);

const StatsCards = () => {
  const { data } = useData();

  if (!data) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="dashboard-card h-24 animate-pulse">
            <div className="h-4 bg-dark-700 rounded w-1/2 mb-2"></div>
            <div className="h-6 bg-dark-700 rounded w-1/4"></div>
          </div>
        ))}
      </div>
    );
  }

  const isCsv = "suspicious_ports" in data;
  
  const uniqueErrorCodes = !isCsv && data?.issues?.Errors 
    ? new Set(data.issues.Errors).size 
    : (!isCsv && data?.issues_detected?.Errors 
      ? new Set(data.issues_detected.Errors).size 
      : 0);

  let stats;
  
  if (isCsv) {
    stats = [
      { 
        title: "Suspicious Ports", 
        value: data?.suspicious_ports?.length || 0, 
        icon: <AlertIcon className="h-5 w-5" />,
        colorClass: "text-danger-500"
      },
      { 
        title: "Brute Force Attacks", 
        value: data?.attacks?.["Brute Force"]?.length || 0, 
        icon: <AttackIcon className="h-5 w-5" />,
        colorClass: "text-warning-500"
      },
      { 
        title: "Credential Stuffing", 
        value: data?.attacks?.["Credential Stuffing"]?.length || 0, 
        icon: <WarningIcon className="h-5 w-5" />,
        colorClass: "text-warning-500"
      },
      { 
        title: "Privilege Escalation", 
        value: data?.attacks?.["Privilege Escalation"]?.length || 0, 
        icon: <AttackIcon className="h-5 w-5" />,
        colorClass: "text-danger-500"
      },
      { 
        title: "Total Attacks", 
        value: Object.values(data?.attacks || {}).reduce((acc, arr) => acc + arr.length, 0),
        icon: <ErrorIcon className="h-5 w-5" />,
        colorClass: "text-primary-500"
      }
    ];
  } else {
    const issuesSource = data.issues_detected || data.issues || {};
    
    stats = [
      { 
        title: "Suspicious Events", 
        value: data?.suspicious_events?.length || 0, 
        icon: <AlertIcon className="h-5 w-5" />,
        colorClass: "text-warning-500"
      },
      { 
        title: "Errors", 
        value: issuesSource?.Errors?.length || 0, 
        icon: <ErrorIcon className="h-5 w-5" />,
        colorClass: "text-danger-500"
      },
      { 
        title: "Warnings", 
        value: issuesSource?.Warnings?.length || 0, 
        icon: <WarningIcon className="h-5 w-5" />,
        colorClass: "text-warning-500" 
      },
      { 
        title: "Failures", 
        value: issuesSource?.Failures?.length || 0, 
        icon: <ErrorIcon className="h-5 w-5" />,
        colorClass: "text-danger-500"
      },
      { 
        title: "Unique Error Codes", 
        value: uniqueErrorCodes, 
        icon: <UniqueIcon className="h-5 w-5" />,
        colorClass: "text-primary-500"
      }
    ];
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {stats.map((stat, index) => (
        <StatCard
          key={index}
          title={stat.title}
          value={stat.value}
          icon={stat.icon}
          colorClass={stat.colorClass}
        />
      ))}
    </div>
  );
};

export default StatsCards;