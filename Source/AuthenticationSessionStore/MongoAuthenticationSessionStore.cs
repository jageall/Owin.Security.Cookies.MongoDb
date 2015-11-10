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
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using MongoDB.Driver;
using MongoDB.Driver.Wrappers;
using MongoDB.Bson;
using MongoDB.Driver.Builders;

namespace Owin.Security.Cookies.MongoDB
{
    public class MongoAuthenticationSessionStore : IAuthenticationSessionStore
    {
        private readonly MongoAuthenticationSessionStoreOptions _options;
        private readonly MongoDatabase _db;
        private readonly string _collection;

        public MongoAuthenticationSessionStore(MongoAuthenticationSessionStoreOptions options)
        {
            _options = options;
            var connection = new MongoClient(options.ConnectionString).GetServer();
            _db = connection.GetDatabase(options.Database);
            _collection = options.Collection;
            EnsureTtlIndexForAuthenticationTickets(_db,_collection);
        }

        private MongoCollection<BsonDocument> Collection
        {
            get { return _db.GetCollection(_collection); }
        }

        public Task<string> StoreAsync(AuthenticationTicket ticket)
        {
            return Save(ticket);
        }

        private Task<string> Save(AuthenticationTicket ticket)
        {
            var key = Guid.NewGuid().ToString("N");
            Collection.Save(Serialize(ticket, key));
            return Task.FromResult(key);
        }

        private BsonDocument Serialize(AuthenticationTicket ticket, string key)
        {
            var doc = new BsonDocument();
            doc["_id"] = key;
            var expires = ticket.Properties.ExpiresUtc ?? _options.Clock().Add(_options.DefaultExpiry);
            doc["_expires"] = BsonTypeMapper.MapToBsonValue(expires, BsonType.DateTime);
            var claimsIdentity = ticket.Identity;
            var identity = new BsonDocument();
            identity["authenticationType"] = claimsIdentity.AuthenticationType;
            var claims = new BsonArray();
            foreach (var claim in claimsIdentity.Claims)
            {
                var c = new BsonDocument();
                c["type"] = claim.Type;
                c["value"] = claim.Value;
                claims.Add(c);
            }
            identity["claims"] = claims;
            doc["identity"] = identity;
            var props = new BsonArray();
            foreach (var prop in ticket.Properties.Dictionary)
            {
                var p = new BsonDocument();
                p["key"] = prop.Key;
                p["value"] = prop.Value;
                props.Add(p);
            }
            doc["properties"] = props;
            return doc;
        }

        public Task RenewAsync(string key, AuthenticationTicket ticket)
        {
            Collection.Save(Serialize(ticket, key));
            return Task.FromResult(0);
        }

        public Task<AuthenticationTicket> RetrieveAsync(string key)
        {
            var tcs = new TaskCompletionSource<AuthenticationTicket>();
            try
            {
                AuthenticationTicket ticket = null;
                var result = Collection.FindOneById(key);
                if (result != null)
                {
                    var identity = ReadIdentity(result);
                    var properties = ReadProperties(result);
                    ticket = new AuthenticationTicket(
                        identity,
                        properties);
                }
                tcs.SetResult(ticket);
            } catch (Exception ex)
            {
                tcs.SetException(ex);
            }
            return tcs.Task;
        }

        private static AuthenticationProperties ReadProperties(BsonDocument result)
        {
            var props = result["properties"].AsBsonArray;
            var properties = new Dictionary<string, string>();
            foreach (var prop in props)
            {
                var key = prop["key"].AsString;
                var value = prop["value"].AsString;
                properties.Add(key, value);
            }
            var p = new AuthenticationProperties(properties);
            return p;
        }

        private static ClaimsIdentity ReadIdentity(BsonDocument result)
        {
            var identity = result["identity"].AsBsonDocument;
            var authenticationType = identity["authenticationType"].AsString;
            var claims = identity["claims"].AsBsonArray;
            var claimset = new List<Claim>();
            foreach (var claim in claims)
            {
                var type = claim["type"].AsString;
                var value = claim["value"].AsString;
                claimset.Add(new Claim(type, value));
            }
            var id = new ClaimsIdentity(claimset, authenticationType);
            return id;
        }

        private static void EnsureTtlIndexForAuthenticationTickets(MongoDatabase mongoDatabase, string collectionName)
        {
            var index = IndexKeys.Ascending("_expires");

            var indexOptions = new IndexOptionsBuilder()
                .SetTimeToLive(TimeSpan.FromSeconds(1))
                .SetBackground(true);
            var collection = mongoDatabase.GetCollection(collectionName);
            collection.EnsureIndex(index, indexOptions);
        }

        public Task RemoveAsync(string key)
        {
            Collection.Remove(new QueryWrapper(new { _id = key }));
            return Task.FromResult(0);
        }
    }
}
