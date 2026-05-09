FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["TlsLab.csproj", "./"]
RUN dotnet restore "TlsLab.csproj"
COPY . .
RUN dotnet publish "TlsLab.csproj" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app
COPY --from=build /app/publish .
COPY cert.pem .
COPY key.pem .

EXPOSE 7266

ENV ASPNETCORE_URLS=https://+:7266

ENTRYPOINT ["dotnet", "TlsLab.dll"]
