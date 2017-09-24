using System;
using System.Linq;
using System.Threading.Tasks;
using VirusTotalNET.Helpers;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;
using VirusTotalNET.UnitTests.TestInternals;
using Xunit;

namespace VirusTotalNET.UnitTests
{
    public class CommentTests : TestBase
    {
        [Fact]
        public async Task CreateValidComment()
        {
            CreateCommentResult comment = await VirusTotal.CreateCommentAsync(TestData.TestHash, "VirusTotal.NET test - " + DateTime.UtcNow.ToString("O"));
            Assert.Equal(CommentResponseCode.Success, comment.ResponseCode);
            Assert.Equal("Your comment was successfully posted", comment.VerboseMsg);
        }

        [Fact]
        public async Task CreateCommentOnUnknownResource()
        {
            CreateCommentResult comment = await VirusTotal.CreateCommentAsync(TestData.GetRandomSHA1s(1).First(), "VirusTotal.NET test - " + DateTime.UtcNow.ToString("O"));
            Assert.Equal(CommentResponseCode.Error, comment.ResponseCode);
            Assert.Equal("Could not find resource", comment.VerboseMsg);
        }

        [Fact]
        public async Task CreateDuplicateComment()
        {
            CreateCommentResult comment = await VirusTotal.CreateCommentAsync(TestData.TestHash, "VirusTotal.NET test");
            Assert.Equal(CommentResponseCode.Error, comment.ResponseCode);
            Assert.Equal("Duplicate comment", comment.VerboseMsg);
        }

        [Fact]
        public async Task CreateLargeComment()
        {
            byte[] content = new byte[1024 * 4];
            string contentInHex = HashHelper.ByteArrayToHex(content); //2x size now

            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await VirusTotal.CreateCommentAsync(TestData.TestHash, contentInHex));
        }

        [Fact]
        public async Task CreateEmptyComment()
        {
            await Assert.ThrowsAsync<ArgumentException>(async () => await VirusTotal.CreateCommentAsync(TestData.TestHash, string.Empty));
        }

        //[Fact]
        //public async Task GetComment()
        //{
        //    CommentResult comment = await VirusTotal.GetCommentAsync(TestData.TestHash);
        //}

        //[Fact]
        //public async Task GetCommentOnUnknownResource()
        //{
        //    CommentResult comment = await VirusTotal.GetCommentAsync(TestData.GetRandomSHA1s(1).First());
        //}

        //[Fact]
        //public async Task GetCommentWithBefore()
        //{
        //    CommentResult comment = await VirusTotal.GetCommentAsync(TestData.TestHash, DateTime.UtcNow); //TODO: before
        //}
    }
}
