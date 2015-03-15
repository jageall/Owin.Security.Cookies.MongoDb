/*
 * Copyright 2014, 2015 James Geall
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
using System;
using System.Collections.ObjectModel;
using System.Security.Claims;
using Microsoft.Owin.Security;
using MongoDB.Bson;
using MongoDB.Driver;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.Cookies.MongoDB;
using Xunit;

namespace Tests
{
    public class MongoAuthenticationSessionStoreTests
    {
        private readonly MongoAuthenticationSessionStore _store;
        private readonly MongoCollection<BsonDocument> _collection;

        public MongoAuthenticationSessionStoreTests()
        {
            var connectionString = "mongodb://localhost";
            var database = "auth_session_test";
            var collection = "AuthenticationTickets";
            var options = new MongoAuthenticationSessionStoreOptions()
                {Database = database};
            _store = new MongoAuthenticationSessionStore(options);

            var db = new MongoClient(connectionString).GetServer().GetDatabase(database);
            _collection = db.GetCollection<BsonDocument>(collection);
        }

        [Fact]
        public void CanStoreAuthenticationTickets()
        {
            var result = _store.StoreAsync(CreateAuthenticationTicket()).Result;
            Assert.NotNull(result);
            Assert.NotEmpty(result);
            AssertStored(result);
        }

        [Fact]
        public void CanRefreshAuthenticationTickets()
        {
            var authenticationTicket = CreateAuthenticationTicket();
            var result = _store.StoreAsync(authenticationTicket).Result;
            var expiresUtc = authenticationTicket.Properties.ExpiresUtc.Value.AddHours(1);
            authenticationTicket.Properties.ExpiresUtc = expiresUtc;
            _store.RenewAsync(result, authenticationTicket);
            Assert.NotNull(result);
            Assert.NotEmpty(result);
            AssertStored(result,expiresUtc);
        }

        [Fact]
        public void CanRemoveAuthenticationTickets()
        {
            var authenticationTicket = CreateAuthenticationTicket();
            var key = _store.StoreAsync(authenticationTicket).Result;
            _store.RemoveAsync(key).Wait();
            var result = _store.RetrieveAsync(key).Result;
            Assert.Null(result);
        }

        [Fact]
        public void CanReadAuthenticationTicket()
        {
            var authenticationTicket = CreateAuthenticationTicket();
            var key = _store.StoreAsync(authenticationTicket).Result;
            var read = _store.RetrieveAsync(key).Result;
            var serializer = new JsonSerializer(){ReferenceLoopHandling = ReferenceLoopHandling.Ignore};
            Assert.Equal(
                JObject.FromObject(authenticationTicket, serializer).ToString(),
                JObject.FromObject(read, serializer).ToString());
        }

        private void AssertStored(string key, DateTimeOffset? expiryTime = null)
        {
            expiryTime = expiryTime ?? DefaultTime();
            var result = _collection.FindOneById(key);
            Assert.NotNull(result);
            var mv = BsonTypeMapper.MapToBsonValue(expiryTime, BsonType.DateTime);
            Assert.Equal(mv, result["_expires"]);
        }

        private AuthenticationTicket CreateAuthenticationTicket()
        {
            var identity = new ClaimsIdentity(new[] { new Claim("a", "b"), new Claim("c", "d"), new Claim("sub", Guid.NewGuid().ToString()),  }, "test");
            var properties = new AuthenticationProperties() { AllowRefresh = false, ExpiresUtc = DefaultTime() };
            return new AuthenticationTicket(identity, properties);
        }

        private static DateTimeOffset DefaultTime()
        {
            return new DateTimeOffset(2000, 1, 1, 1, 1, 1, TimeSpan.Zero);
        }
    }
}
