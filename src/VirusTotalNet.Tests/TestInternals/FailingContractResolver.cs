using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace VirusTotalNet.Tests.TestInternals;
//This code comes from: https://github.com/LordMike/TMDbLib/blob/master/TMDbLibTests/JsonHelpers/FailingContractResolver.cs

public class FailingContractResolver : DefaultContractResolver
{
    protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
    {
        JsonProperty res = base.CreateProperty(member, memberSerialization);

        // If we haven't explicitly stated that a field is not needed, we require it for compliance
        if (!res.Ignored)
            res.Required = Required.AllowNull;

        return res;
    }
}