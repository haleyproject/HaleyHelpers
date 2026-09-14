namespace Haley.Models
{
    public enum DeploymentGrantState
    {
        Missing = 0,
        Trial = 1,
        TrialExpired = 2,
        Valid = 3,
        Expiring = 4,
        Grace = 5,
        Expired = 6,
        MissingVerifier = 7,
        MachineEvidenceUnavailable = 8,
        MachineMismatch = 9,
        InvalidDeployment = 10,
        TamperedRequest = 11,
        TamperedGrant = 12,
        InvalidRequest = 13,
        InvalidGrant = 14,
        NotYetValid = 15,
        RequestUnavailable = 16,
        Unrestricted = 17
    }
}
